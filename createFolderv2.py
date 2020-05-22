#!/usr/bin/env python
import argparse
import logging
import os
import sys
import xml.etree.ElementTree
import jenkins

FARM_LIST = {'local': 'http://localhost:8080/'}
PERMISSION_LIST = {
    "build": ['hudson.model.Item.Build'],
    "devA": ['hudson.model.Item.Create', 'hudson.model.Item.Build'],
    "devB": ['hudson.model.Item.Delete', 'hudson.model.Item.Build']
}


def init_logger():
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)


def parse_arguments(arguments):
    parser = argparse.ArgumentParser()
    parser.add_argument('--farm', help="Jenkins farm name", type=str, required=True)
    parser.add_argument('--folder', help="Folder name to create/update", type=str, required=True)
    parser.add_argument('--user', help="User on farm to grant access", type=str, required=True)
    parser.add_argument('--permission', help="Permission(s) for user csv.", type=str, required=True)
    return parser.parse_args(arguments)


def validate_farm(farm):
    valid = True
    if farm not in FARM_LIST.keys():
        valid = False
    return valid


def validate_and_get_permission(permission_csv, user_csv):
    jenkins_perms = []
    perms = permission_csv.split(',')
    users = user_csv.split(',')
    for user in users:
        for grp in perms:
            if grp in PERMISSION_LIST.keys():
                for perm in PERMISSION_LIST[grp]:
                    jenkins_perms.append("{}:{}".format(perm, user))
            else:
                logging.warning("Unknown permission '{}' skipping it.".format(grp))
    return jenkins_perms


def build_payload_xml(permissions, config_xml_str):
    root = xml.etree.ElementTree.XML(config_xml_str)
    auth_mat = root.find('properties/com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty')
    if auth_mat is None:
        folder_props = root.find('properties')
        auth_mat = folder_props.makeelement(
            'com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty', {})
        folder_props.append(auth_mat)
        inheritance_strategy = auth_mat.makeelement('inheritanceStrategy', {
            "class": "org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy"})
        auth_mat.append(inheritance_strategy)
    for perm in permissions:
        perm_element = xml.etree.ElementTree.SubElement(auth_mat, 'permission', {})
        perm_element.text = perm
    return xml.etree.ElementTree.tostring(root, encoding='utf-8')


if __name__ == '__main__':
    # noinspection PyBroadException
    try:
        init_logger()
        args = parse_arguments(sys.argv[1:])
        if not validate_farm(args.farm):
            logging.error("Farm name '{}' not defined.".format(args.farm))
            sys.exit(-1)
        permission_to_add = validate_and_get_permission(args.permission, args.user)
        logging.debug(permission_to_add)  # debug
        folder_name_to_create = args.folder
        jenkins_url = FARM_LIST.get(args.farm)
        jenkins_server = jenkins.Jenkins(jenkins_url, username=os.environ.get('JENKINS_API_USER'),
                                         password=os.environ.get('JENKINS_API_TOKEN'))
        folderExist = jenkins_server.job_exists(folder_name_to_create)
        if folderExist:
            config_xml = jenkins_server.get_job_config(folder_name_to_create)
        else:
            config_xml = jenkins.EMPTY_FOLDER_XML
        xml_payload = build_payload_xml(permission_to_add, config_xml).decode("utf-8")
        jenkins_server.upsert_job(folder_name_to_create, xml_payload)
        logging.info("Success: Folder created/updated.")
    except jenkins.JenkinsException as je:
        if str(je).find('folder for the job does not exist') > 0:
            logging.error("Please check folder path is invalid")
        elif str(je).find('authentication failed') > 0:
            logging.error("Please check JENKINS_API_USER/JENKINS_API_TOKEN env vars are valid.")
        else:
            logging.error(je)
    except Exception as e:
        logging.error("Unknown error: ")
        sys.exit(-1)
