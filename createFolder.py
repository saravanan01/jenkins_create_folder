#!/usr/bin/env python
import argparse
import os
import sys
import requests
from requests.auth import HTTPBasicAuth
import xml.etree.ElementTree as ET

TIMEOUT_HTTP = 10  # http call timeout in secs

FARM_LIST = {'local': 'http://localhost:8080/'}

PERMISSION_LIST = {
    "build": ['hudson.model.Item.Build'],
    "devA":  ['hudson.model.Item.Create', 'hudson.model.Item.Build']
}


def parse_arguments(arguments):
    parser = argparse.ArgumentParser()
    parser.add_argument('--farm', help="Jenkins farm name", type=str, required=True)
    parser.add_argument('--folder', help="Folder name to create", type=str, required=True)
    parser.add_argument('--folder_path', help="Folder path for new folder", type=str, required=False, default='/')
    parser.add_argument('--user', help="User on farm to grant access", type=str, required=True)
    parser.add_argument('--permission', help="Permission(s) for user csv.", type=str, required=True)
    args = parser.parse_args(arguments)
    return args


def validate_farm(farm):
    valid = True
    if farm not in FARM_LIST.keys():
        print("Farm name '{}' not defined.".format(farm))
        valid = False
    return valid


def validate_and_get_permission(permission_csv, user_csv):
    jenkins_perms = []
    perms = permission_csv.split(',')
    users = user_csv.split(',')
    for user in users:
        for grp in perms:
            if grp in PERMISSION_LIST.keys():
                for permz in PERMISSION_LIST[grp]:
                    jenkins_perms.append("{}:{}".format(permz, user))
            else:
                print("Unknown permission '{}' skipping it.".format(p))
    return jenkins_perms


def jenkins_call_get_config_file(url, auth_value, file_name, folder_path='/'):
    temp_folder_name = "temp_folder_DELETE_THIS"
    resp = requests.post(
        "{}/{}/createItem".format(url, folder_path),
        params={"name": temp_folder_name, "mode": "com.cloudbees.hudson.plugins.folder.Folder"},
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        auth=auth_value,
        timeout=TIMEOUT_HTTP)
    if resp.status_code != 200:
        print("failed to connect to jenkins. status code: " + str(resp.status_code))
        raise IOError
    resp = requests.get(
        "{}/{}/job/{}/config.xml".format(url, folder_path, temp_folder_name),
        auth=auth_value,
        timeout=TIMEOUT_HTTP)
    if resp.status_code != 200:
        print("failed to connect to jenkins to read temp config file. status code: " + str(resp.status_code))
        raise IOError
    else:
        with open(file_name, 'wb') as f:
            f.write(resp.content)
    # print("trying to deleting temp folder")
    resp = requests.post(
        "{}/{}job/{}/doDelete".format(url, folder_path, temp_folder_name),
        auth=auth_value,
        timeout=TIMEOUT_HTTP)
    if resp.status_code != 200:
        print("Failed to delete temp folder.")


def jenkins_call_create_folder(url, folder_name, template_file, auth_value, permission_to_add, folder_path='/'):
    print("creating folder...")
    xml_payload = build_payload_xml(permission_to_add, template_file)

    resp = requests.post(
        "{}/{}/createItem".format(url,folder_path),
        params={"name": folder_name},
        data=xml_payload,
        headers={'Content-Type': 'application/xml'},
        auth=auth_value,
        timeout=TIMEOUT_HTTP)
    if resp.status_code != 200:
        if resp.status_code == 400:
            print("error.. check if folder already exist...")
            raise FileExistsError
        else:
            print("Failed to create folder. Status" + str(resp.status_code))
    else:
        print("Success: Folder created.")


def build_payload_xml(permission_to_add, template_file):
    tree = ET.parse(template_file)
    root = tree.getroot()
    folder_props = root.find('properties')
    auth_mat = folder_props.makeelement('com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty',
                                        {})
    folder_props.append(auth_mat)
    inheritance_strategy = auth_mat.makeelement('inheritanceStrategy', {
        "class": "org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy"})
    auth_mat.append(inheritance_strategy)
    for perm in permission_to_add:
        perm_element = ET.SubElement(auth_mat, 'permission', {})
        perm_element.text = perm
    return ET.tostring(root)


if __name__ == '__main__':
    tmp_file_name = 'folder_config_template.xml'
    try:
        args = parse_arguments(sys.argv[1:])
        if not validate_farm(args.farm):
            sys.exit(-1)

        jenkins_perms = validate_and_get_permission(args.permission, args.user)
        # print(jenkins_perms)
        jenkins_url = FARM_LIST.get(args.farm)
        auth = HTTPBasicAuth(os.environ.get('JENKINS_API_USER'), os.environ.get('JENKINS_API_TOKEN'))
        jenkins_call_get_config_file(jenkins_url, auth, tmp_file_name, args.folder_path)
        jenkins_call_create_folder(jenkins_url, args.folder, tmp_file_name, auth, jenkins_perms, args.folder_path)
        os.remove(tmp_file_name)
    except:
        try:
            os.remove(tmp_file_name)
        except OSError:
            pass
        sys.exit(-1)
