

import platform
import os
import subprocess
import sys
import shutil
import gzip
import tarfile
import re
import argparse
import glob
import requests
import io
import datetime
import hashlib
from io import BytesIO
import xml.etree.ElementTree as ET
import urllib.request
import json
from os.path import expanduser
import http.client
import zipfile

NONE = 0
INFO = 1
VERBOSE = 2
DEBUG = 3


####################################################################################################
# Replace the variables using a dictionary
####################################################################################################

def multipleReplace(text, wordDict):
    for key in wordDict:
        text = text.replace('${' + key + '}', wordDict[key])
    return text

####################################################################################################
# Calculate MD5 hash of a file
####################################################################################################

def info(config):
    return config['level'] >= INFO

def verbose(config):
    return config['level'] >= VERBOSE

def debug(config):
    return config['level'] >= DEBUG

####################################################################################################
# Calculate MD5 hash of a file
####################################################################################################

def md5(file):
    hash_md5 = hashlib.md5()
    file.seek(0, os.SEEK_SET)
    for chunk in iter(lambda: file.read(4096), b""):
        hash_md5.update(chunk)
    return hash_md5.hexdigest()

####################################################################################################
# Calculate SHA1 hash of a file
####################################################################################################

def sha1(file):
    hash_sha1 = hashlib.sha1()
    file.seek(0, os.SEEK_SET)
    for chunk in iter(lambda: file.read(4096), b""):
        hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

####################################################################################################
# Find a program on the PATH
####################################################################################################

def which(program):
    import os
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

####################################################################################################
# inplace_change
####################################################################################################

def inplace_change(filename, old_string, new_string):
    # Safely read the input filename using 'with'
    with open(filename) as f:
        s = f.read()
        if old_string not in s:
            # print('"{old_string}" not found in {filename}.'.format(**locals()))
            return

    # Safely write the changed content, if found in the file
    with open(filename, 'w') as f:
        # print('Changing "{old_string}" to "{new_string}" in {filename}'.format(**locals()))
        s = s.replace(old_string, new_string)
        f.write(s)


####################################################################################################
# Run a program and wait for the result
####################################################################################################

def runProgram(config, workingDirectory, environment, arguments):

    if verbose(config):
        print('------------------------------------------------------------------------------------')
        print('subprocess:', arguments)
        print('workingDirectory = ' + workingDirectory)
        #print('environment:', environment)

    p = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, cwd=workingDirectory)
    stdout = p.stdout.read().decode('utf-8')
    stderr = p.stderr.read().decode('utf-8')
    returncode = p.returncode

    if verbose(config):
        print('---------[ stdout ]-----------------------------------------------------------------')
        print(stdout)
        print('---------[ stderr ]-----------------------------------------------------------------')
        print(stderr)
        print('---------[ exitCode ]---------------------------------------------------------------')
        print(returncode)
        print('------------------------------------------------------------------------------------')

    return stdout, stderr, returncode



####################################################################################################
# Parse the version from the metadata
####################################################################################################

def parseReleaseNumberFromMetadata(content):

    if args.debug:
        print("parseReleaseNumberFromMetadata:")

    root = ET.fromstring(content)

    versioning = root.find('versioning')
    if versioning == None:
        print('Error parsing metadata: Could not find the \'versioning\' tag')
        print('content:')
        print(content)
        sys.exit(3)

    release = versioning.find('release')
    if release == None:
        print('Error parsing metadata: Could not find the \'release\' tag')
        print('content:')
        print(content)
        sys.exit(5)

    if args.debug:
        print('    release =', release.text)

    return release.text


####################################################################################################
# Parse the build number from the metadata
####################################################################################################

def parseSnapshotInfoFromMetadata(config, content):

    if debug(config):
        print("parseSnapshotInfoFromMetadata:")

    root = ET.fromstring(content)

    versioning = root.find('versioning')
    if versioning == None:
        print('Error parsing metadata: Could not find the \'versioning\' tag')
        print('content:')
        print(content)
        sys.exit(3)

    snapshot = versioning.find('snapshot')
    if snapshot == None:
        print('Error parsing metadata: Could not find the \'snapshot\' tag')
        print('content:')
        print(content)
        sys.exit(4)

    timestamp = snapshot.find('timestamp')
    if timestamp == None:
        print('Error parsing metadata: Could not find the \'timestamp\' tag')
        print('content:')
        print(content)
        sys.exit(5)

    buildNumber = snapshot.find('buildNumber')
    if buildNumber == None:
        print('Error parsing metadata: Could not find the \'buildNumber\' tag')
        print('content:')
        print(content)
        sys.exit(5)

    if debug(config):
        print('    buildNumber =', buildNumber.text)
        print('    timestamp =', timestamp.text)

    info = {'buildNumber': int(buildNumber.text), 'timestamp': timestamp.text}
    return info


####################################################################################################
# Read the metadata and return the version
####################################################################################################

def getSnapshotInfoFromDistributionMetadata(config, mavenGroupId, mavenArtifactId, version):

    snapshotInfo = None

    if debug(config):
        print('getSnapshotInfoFromDistributionMetadata(1):')
        print('    mavenGroupId = ' + mavenGroupId)
        print('    mavenArtifactId = ' + mavenArtifactId)
        print('    version = ' + version)

    deployment = config['distributionManagement']['repository']['deployment']
    repositoryUrl = multipleReplace(deployment['url'], config['properties'])
    metadataUrl = repositoryUrl + '/' + mavenGroupId.replace('.', '/') + '/' + mavenArtifactId  + '/' + version + '/' + 'maven-metadata.xml'

    if debug(config):
        print('    repositoryUrl = ' + repositoryUrl)
        print('    metadataUrl = ' + metadataUrl)

    # Get the metadata to discover the current build number
    r = requests.get(metadataUrl, stream=True)

    # Use the metadata file to work out the build number
    if r.status_code == 200: # http.HTTPStatus.OK.value
        if debug(config):
            print('getSnapshotInfoFromDistributionMetadata(2)')
            print('    Artifact was found in Nexus')

        snapshotInfo = parseSnapshotInfoFromMetadata(config, r.text)

    elif r.status_code == 404: # http.HTTPStatus.NOT_FOUND.value
        if debug(config):
            print('getSnapshotInfoFromDistributionMetadata(3)')
            print('    Artifact not found in Nexus')

    else:
        print('Unexpected Http response ' + str(r.status_code) + ' when getting: maven-metadata.xml')
        print('    metadataUrl: ' + metadataUrl)
        content = r.raw.decode('utf-8')
        print('Content =', content)
        sys.exit(99)

    return snapshotInfo


####################################################################################################
# Read the metadata and return the version
####################################################################################################

def getSnapshotInfoFromRepositoryMetadata(config, repositoryUrl, mavenGroupId, mavenArtifactId, version):

    snapshotInfo = None

    if debug(config):
        print('getSnapshotInfoFromRepositoryMetadata:')
        print('    repositoryUrl = ' + repositoryUrl)
        print('    mavenGroupId = ' + mavenGroupId)
        print('    mavenArtifactId = ' + mavenArtifactId)
        print('    version = ' + version)

    metadataUrl = repositoryUrl + '/' + mavenGroupId.replace('.', '/') + '/' + mavenArtifactId + '/' + version + '/' + 'maven-metadata.xml'

    if debug(config):
        print('    metadataUrl = ' + metadataUrl)

    # Get the metadata to discover the current build number
    r = requests.get(metadataUrl, stream=True)

    # Use the metadata file to work out the build number
    if r.status_code == 200: # http.HTTPStatus.OK.value
        if debug(config):
            print('    Artifact was found in Remote Repository')

        snapshotInfo = parseSnapshotInfoFromMetadata(config, r.text)

    elif r.status_code == 404: # http.HTTPStatus.NOT_FOUND.value
        if debug(config):
            print('    Artifact not found in Remote Repository')

    else:
        print('Unexpected Http response ' + str(r.status_code) + ' when getting: maven-metadata.xml')
        print('    metadataUrl: ' + metadataUrl)
        content = r.raw.decode('utf-8')
        print('Content =', content)
        sys.exit(99)

    return snapshotInfo


####################################################################################################
# Get the server credentials from the maven xml settings file
####################################################################################################

def getServersConfigurationFromSettingsFile(config):

    if verbose(config):
        print('getServersConfigurationFromSettingsFile:')

    home = expanduser('~')
    settingsfile = os.path.abspath(home + '/.m2/settings.xml')

    if os.path.exists(settingsfile):
        if verbose(config):
            print('Found settings file = ' + settingsfile)
    else:
        print('Settings file NOT found = ' + settingsfile)
        sys.exit(3)

    # instead of ET.fromstring(xml)
    it = ET.iterparse(settingsfile)
    for _, el in it:
        if '}' in el.tag:
            el.tag = el.tag.split('}', 1)[1]  # strip all namespaces
    root = it.root

    xmlServers = root.find('servers')
    if xmlServers == None:
        print('Error parsing settings file: Could not find the \'servers\' tag')
        sys.exit(3)

    found = None
    servers = {}
    for xmlServer in xmlServers:

        id = None
        username = None
        password = None

        if debug(config):
            print('    server:')
        for item in xmlServer:
            if debug(config):
                value = 'None'
                if item.text != None:
                    value = item.text
                print('        tag: ' + item.tag + ' : ' + value)

            if item.tag == 'id':
                id = item.text
            elif item.tag == 'username':
                username = item.text
            elif item.tag == 'password':
                password = item.text

        server = {'username': username, 'password': password}
        servers[id] = server

    if verbose(config):
        print('    servers:')
        for item in servers.items():
            id = item[0]
            print('        ' + id + ': ( ' + servers[id]['username'] + ' : ' + servers[id]['password'] + ' )')

    return servers


####################################################################################################
# Delete a URL resource
#
# Make the Nexus repository rebuild its metadata
# curl -v --request DELETE  --user "login:password"  --silent http://nexusHost/service/local/metadata/repositories/myRepository/content
#
####################################################################################################

def rebuildMetadata(config, filepath):

    if verbose(config):
        print('rebuildMetadata:')
        print('    filepath =', filepath)

    admin = config['distributionManagement']['repository']['admin']
    repositoryId = multipleReplace(admin['id'], config['properties'])
    repositoryUrl = multipleReplace(admin['url'], config['properties'])
    url = repositoryUrl + '/' + filepath + '/'

    if debug(config):
        print('rebuildMetadata')
        print('    repositoryId = ' + repositoryId)
        print('    repositoryUrl = ' + repositoryUrl)
        print('    url = ' + url)

    servers = config['servers']
    server = servers[repositoryId]
    username = server['username']
    password = server['password']

    if debug(config):
        print('    username = ' + username)
        print('    password = ' + password)

    r = requests.delete(url, auth=(username, password))
    statusCode = r.status_code

    if verbose(config):
        print('    statusCode = ' + str(statusCode) + ' : ' + http.client.responses[statusCode])

    if statusCode > 400:
        sys.exit(3)

    return statusCode


####################################################################################################
# Upload a stream to a URL
####################################################################################################

def uploadFile(config, file, repositoryID, url):

    if verbose(config):
        print('uploadFile:')
        print('    repositoryID =', repositoryID)
        print('    url =', url)


    file.seek(0, os.SEEK_END)
    fileSize = file.tell()

    file.seek(0, os.SEEK_SET)


    servers = config['servers']
    server = servers[repositoryID]

    if debug(config):
        print('    username = ' + server['username'])
        print('    password = ' + server['password'])

    r = requests.post(url, data=file, auth=(server['username'], server['password']))
    statusCode = r.status_code

    if verbose(config):
        print('    statusCode = ' + str(statusCode) + ' : ' + http.client.responses[statusCode])

    if statusCode >= 400:
        sys.exit(3)

    return statusCode


####################################################################################################
# Upload a string
####################################################################################################

def uploadString(config, string, repositoryID, url):

    if verbose(config):
        print('uploadString')
        print('    repositoryID =', repositoryID)
        print('    string =', string)

    file = io.BytesIO(string.encode('utf-8'))
    uploadFile(config, file, repositoryID, url)
    file.close()


####################################################################################################
# Upload a file and its metadata to Artifact
####################################################################################################

def uploadFileAndHashes(config, file, filePath, fileName, packaging):

    if verbose(config):
        print('uploadFileAndHashes(1):')
        print('    filePath =', filePath)
        print('    fileName =', fileName)
        print('    packaging =', packaging)

    deployment = config['distributionManagement']['repository']['deployment']
    repositoryId = multipleReplace(deployment['id'], config['properties'])
    repositoryUrl = multipleReplace(deployment['url'], config['properties'])
    url = repositoryUrl + '/' + filePath + '/' + fileName + '.' + packaging

    if debug(config):
        print('uploadFileAndHashes(2)')
        print('    repositoryId =', repositoryId)
        print('    repositoryUrl =', repositoryUrl)
        print('    url = ', url)

    uploadFile(config, file, repositoryId, url)
    uploadString(config, md5(file), repositoryId, url + '.md5')
    uploadString(config, sha1(file), repositoryId, url + '.sha1')


####################################################################################################
# Make POM
####################################################################################################

def makePom(config, mavenGroupId, mavenArtifactId, version, packaging):

    lines = []
    lines.append('<?xml version="1.0" encoding="UTF-8"?>\n')
    lines.append('<project xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd" xmlns="http://maven.apache.org/POM/4.0.0"\n')
    lines.append('    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n')
    lines.append('  <modelVersion>4.0.0</modelVersion>\n')
    lines.append('  <groupId>' + mavenGroupId  + '</groupId>\n')
    lines.append('  <artifactId>' + mavenArtifactId + '</artifactId>\n')
    lines.append('  <version>' + version + '</version>\n')
    lines.append('  <packaging>' + packaging + '</packaging>\n')
    lines.append('</project>\n')

    buffer = BytesIO()
    for line in lines:
        buffer.write(line.encode('utf-8'))

    return buffer


####################################################################################################
# Upload a file and its md5 and its sha1 to Nexus
####################################################################################################

def uploadArtifact(config, mavenGroupId, mavenArtifactId, version, packaging, filename):

    if debug(config):
        print('uploadArtifact:')
        print('    mavenGroupId =', mavenGroupId)
        print('    mavenArtifactId =', mavenArtifactId)
        print('    version =', version)
        print('    packaging =', packaging)
        print('    filename =', filename)

    snap = version.endswith('SNAPSHOT')

    if snap:
        info = getSnapshotInfoFromDistributionMetadata(config, mavenGroupId, mavenArtifactId, version)
        if info == None:
            buildNumber = 1
        else:
            buildNumber = info.get('buildNumber') + 1

        if debug(config):
            print('uploadArtifact(1):')
            print('    buildNumber = ' + str(buildNumber))

        timestamp = '{:%Y%m%d.%H%M%S}'.format(datetime.datetime.now())
        fileName = mavenArtifactId  + '-' + version.replace('SNAPSHOT', timestamp) + '-' + str(buildNumber)
    else:
        fileName = mavenArtifactId  + '-' + version

    filePath = mavenGroupId.replace('.', '/') + '/' + mavenArtifactId
    filePathVersion = filePath + '/' + version

    if debug(config):
        print('uploadArtifact(2):')
        print('    filePath = ' + filePath)
        print('    filePathVersion = ' + filePathVersion)
        print('    fileName = ' + fileName)

    # Upload base file
    file = open(filename, 'rb')
    uploadFileAndHashes(config, file, filePathVersion, fileName, packaging)
    file.close()

    # Upload the pom file
    file = makePom(config, mavenGroupId, mavenArtifactId, version, packaging)

    if debug(config):
        file.seek(0, os.SEEK_SET)
        print('uploadArtifact(2): ')
        print(file.read().decode('utf-8'))

    uploadFileAndHashes(config, file, filePathVersion, fileName, 'pom')
    file.close()

    # Send request to Nexus to rebuild metadata
    rebuildMetadata(config, filePath)


####################################################################################################
# Download a file
####################################################################################################

def downloadFile(config, url, file):

    # Remove any old version of the file
    if os.path.exists(file):
        os.remove(file)

    # Download the file
    r = requests.get(url, stream=True)

    rc = 0
    if r.status_code == 200: # http.HTTPStatus.OK.value
        if debug(config):
            print('downloadFile:')
            print('    File ' + file + ' was found in Nexus')

        directory = os.path.dirname(file)
        if not os.path.exists(directory):
            os.makedirs(directory)

        f = open(file, 'wb')
        for chunk in r.iter_content(chunk_size=512 * 1024):
            if chunk: # filter out keep-alive new chunks
                f.write(chunk)
        f.close()

    elif r.status_code == 404: # http.HTTPStatus.NOT_FOUND.value
        rc = 1
        print('    File not found in Nexus')


    else:
        rc = 2
        print('Unexpected Http response ' + str(r.status_code) + ' when getting: maven-metadata.xml')
        print('    metadataUrl: ' + metadataUrl)
        content = r.raw.decode('utf-8')
        print('Content =', content)
        sys.exit(99)

    return rc


####################################################################################################
# Download a file and its hashes
####################################################################################################

def downloadFileAndHashes(config, url, localfile):

    if debug(config):
        print('downloadFileAndHashes:')
        print('    url =', url)
        print('    localfile =', localfile)

    rc = 0
    if (rc == 0): rc = downloadFile(config, url, localfile)
    if (rc == 0): rc = downloadFile(config, url + '.sha1', localfile + '.sha1')

    return rc


####################################################################################################
# Copy the long snapshot artifact to the short snapshot artifact
####################################################################################################

def copySnapshot(config, localpath, fileNameExpanded, fileName):
    longName = localpath + '/' + fileNameExpanded
    shortName = localpath + '/' + fileName
    shutil.copy2(longName, shortName)


####################################################################################################
# Read the "lastUpdated.json" file
####################################################################################################

def readLastUpdatedFile(config, directory):

    if debug(config):
        print('readLastUpdatedFile:')
        print('    directory = ' + directory)

    filepath = os.path.abspath(directory + '/' + 'lastUpdated.json')

    if not os.path.exists(filepath):
        if verbose(config):
            print('Dependancy not found in local repository')
            print(filepath)
        return None

    data = {}
    with open(filepath) as file:
        data.update(json.load(file))

    lastChecked = data.get('lastChecked')
    now = '{:%Y%m%d.%H%M%S}'.format(datetime.datetime.now())

    print('    now = ' + now)
    print('    lastChecked = ' + lastChecked)

    return lastChecked

####################################################################################################
# Write the "lastUpdated.json" file to the local directory
####################################################################################################

def writeLastUpdatedFile(config, directory):

    if debug(config):
        print('writeLastUpdatedFile:')
        print('    directory = ' + directory)

    timestamp = '{:%Y%m%d.%H%M%S}'.format(datetime.datetime.now())
    data = {'lastChecked': timestamp}

    if not os.path.exists(directory):
        os.makedirs(directory)

    filepath = os.path.abspath(directory + '/' + 'lastUpdated.json')

    with open(filepath, 'w') as outfile:
        json.dump(data, outfile, indent=4, sort_keys=True, separators=(',', ':'))

####################################################################################################
# Download an artifact
####################################################################################################

def downloadArtifact(config, mavenGroupId, mavenArtifactId,  version, packaging):

    if debug(config):
        print('downloadArtifact:')
        print('    mavenGroupId = ' + mavenGroupId)
        print('    mavenArtifactId = ' + mavenArtifactId)
        print('    version = ' + version)
        print('    packaging = ' + packaging)

    snap = version.endswith('SNAPSHOT')

    path = mavenGroupId.replace('.', '/') + '/' + mavenArtifactId + '/' + version

    home = expanduser('~')
    localpath = os.path.abspath(home + '/.m2/repository/' + path)
    fileName = mavenArtifactId + '-' + version

    if debug(config):
        print('    fileName = ' + fileName)
        print('    path = ' + path)
        print('    localpath = ' + localpath)

    lastUpdated = readLastUpdatedFile(config, localpath)

    searchRemoteRepositories = False
    if snap:
        searchRemoteRepositories = True

    elif os.path.exists(localpath + '/' + fileName + '.' + packaging):
        searchRemoteRepositories = False
        if verbose(config):
            print('Artifact already exists in local repository')
    else:
        searchRemoteRepositories = True
        if verbose(config):
            print('Artifact not found in local reposity')

    writeLastUpdatedFile(config, localpath)

    if searchRemoteRepositories:
        print('Looking for artifact in remote repositories')

        for repository in config['repositories']:
            repositoryUrl = multipleReplace(repository["url"], config["properties"])

            if debug(config):
                print('    repositoryUrl = ' + repositoryUrl)

            if snap:
                info = getSnapshotInfoFromRepositoryMetadata(config, repositoryUrl, mavenGroupId, mavenArtifactId, version)
                if info == None:
                    if debug(config):
                        print('    Snapshot not found in Repository')
                    continue
                fileNameExpanded = mavenArtifactId + '-' + version.replace('SNAPSHOT', info.get('timestamp')) + '-' + str(info.get('buildNumber'))
            else:
                fileNameExpanded = mavenArtifactId + '-' + version

            localFilenameExpanded = os.path.abspath(localpath + '/' + fileNameExpanded)
            localFilename = os.path.abspath(localpath + '/' + fileName)

            url = repositoryUrl + '/' + path + '/' + fileNameExpanded

            if debug(config):
                print('downloadArtifact(1):')
                print('    localFilenameExpanded = ' + localFilenameExpanded)
                print('    url = ' + url)

            rc = downloadFileAndHashes(config, url + '.' + packaging, localFilename + '.' + packaging)
            if rc != 0:
                if debug(config):
                    print('    Artifact not found in Repository')
                continue

            downloadFileAndHashes(config, url + '.pom', localFilename + '.pom')

            return

        print('Artifact ' + fileName + ' not found in remote repositories')
        sys.exit(99)


####################################################################################################
# Expand artifact
####################################################################################################

def expandArtifact(config, mavenGroupId, mavenArtifactId, version, packaging, dependancyDirectory):

    if debug(config):
        print('expandArtifact:')
        print('    mavenGroupId = ' + mavenGroupId)
        print('    mavenArtifactId = ' + mavenArtifactId)
        print('    version = ' + version)
        print('    packaging = ' + packaging)
        print('    dependancyDirectory = ' + dependancyDirectory)

    fileName = mavenArtifactId + '-' + version + '.' + packaging

    home = expanduser('~')
    path = mavenGroupId.replace('.', '/') + '/' + mavenArtifactId + '/' + version
    localpath = os.path.abspath(home + '/.m2/repository/' + path + '/' + fileName)
    directory = os.path.abspath(dependancyDirectory + '/' + mavenArtifactId.split('-')[0])

    if debug(config):
        print('expandArtifact:')
        print('    localpath = ' + localpath)
        print('    directory = ' + directory)

    if not os.path.exists(directory):
        os.makedirs(directory)

    with zipfile.ZipFile(localpath, 'r') as z:
        z.extractall(directory)


####################################################################################################
# Main Routine
####################################################################################################

def main(argv, clean, generate, configure, make, distribution, deploy):

    ####################################################################################################
    # Parse command line arguments
    ####################################################################################################

    parser = argparse.ArgumentParser(description='Build and deploy a project.')

    parser.add_argument('goals', type=str, nargs='*', help='A list of build goals [default: all]')
    parser.add_argument("--file", help="Build file [default: build.json]", default='build.json')

    parser.add_argument('-D', dest='properties', action='append', help="Set a system property")
    parser.set_defaults(properties=[])

    parser.add_argument("-i", "--info", help="Set the trace level to 'info'", dest='traceLevel', action='store_const', const=INFO)
    parser.add_argument("--verbose", help="Set the trace level to 'verbose'", dest='traceLevel', action='store_const', const=VERBOSE)
    parser.add_argument("--debug", help="Set the trace level to 'debug'", dest='traceLevel', action='store_const', const=DEBUG)
    parser.set_defaults(traceLevel=NONE)

    args = parser.parse_args()
    config = {}
    config['level'] = args.traceLevel

    if len(args.goals) == 0:
        goals = ['clean', 'generate', 'configure', 'make', 'dist', 'deploy']
    else:
        goals = args.goals

    if verbose(config):
        print('Given goals:  ', args.goals)
        print('Actual goals: ', goals)

    if debug(config):
        print('Number of command-line properties = ' + str(len(args.properties)))
        for property in args.properties:
            print('    ' + property)

    ####################################################################################################
    # Read Configuration files
    ####################################################################################################

    with open(args.file) as buildfile:
        config.update(json.load(buildfile))

    servers = getServersConfigurationFromSettingsFile(config)
    config['servers'] = servers

    properties = config['properties']
    if debug(config):
        print('Number of config properties = ' + str(len(properties)))
        for key in properties:
            print('    ' + key + ' = ' + properties[key])

    for property in args.properties:
        words = property.split('=')
        if len(words) >= 1:
            key = words[0].strip();
            value = None
        if len(words) >= 2:
            key = words[0].strip();
            value = words[1].strip();

        properties[key] = value

    if debug(config):
        print('Number of config properties = ' + str(len(properties)))
        for key in properties:
            print('    ' + key + ' = ' + properties[key])


    ####################################################################################################
    # Detect the environment
    ####################################################################################################
    if platform.system().startswith("Linux"):
        operatingSystem = 'Linux'

    elif platform.system().startswith("CYGWIN"):
        operatingSystem = 'Cygwin'

    elif platform.system().startswith("Windows"):

        if os.environ.get("MSYSTEM"):
            operatingSystem = 'MinGW'

        else:
            operatingSystem = 'Windows'

    else:
        print('The OperatingSystem is not defined')
        sys.exit(1)


    if operatingSystem == 'Windows':
        if os.path.exists(os.environ['ProgramFiles(x86)']):
            architecture = 'x86_64'
        else:
            architecture = 'x86'

        if which('cl.exe'):
            linker = 'msvc'
        else:
            print('The complier CL.EXE is not available')
            sys.exit(1)

        aol = architecture + '-' + operatingSystem + '-' + linker


    elif operatingSystem == 'undefined':
        aol = 'undefined'

    else:
        if which('gcc'):
            gcc = 'gcc'

        elif which('gcc.exe'):
            gcc = 'gcc.exe'

        else:
            print('The Compiler gcc is not available')
            sys.exit(1)

        stdout, stderr, returncode = runProgram(config, os.getcwd(), os.environ, [gcc, '-v'])

        lines = stderr.splitlines()
        for line in lines:
            if line.startswith('Target:'):
                words = line.split()
                aol = words[1]
                break

        string = aol.split('-')
        architecture = string[0]
        operatingSystem = string[1]
        linker = string[2]

    if verbose(config):
        print('architecture    =', architecture)
        print('operatingSystem =', operatingSystem)
        print('linker          =', linker)

    print('AOL =', aol)

    # Windows      x86_64-Windows-msvc
    # Linux        x86_64-linux-gnu
    # Cygwin       x86_64-pc-cygwin
    # MinGW        i686-w64-mingw32

    ####################################################################################################
    # Init
    ####################################################################################################

    src = os.path.abspath('./src')
    build = os.path.abspath('./build')
    source = os.path.abspath(build + '/source')
    sourcesrc = os.path.abspath(source + '/src')
    temp = os.path.abspath(build + '/temp')
    output = os.path.abspath(build + '/output')
    dist = os.path.abspath(build + '/dist')
    dependances = os.path.abspath(build + '/dependances')

    packaging = 'zip'

    ####################################################################################################
    # Call the build processes
    ####################################################################################################

    if 'clean' in goals:
        print('goal = clean')
        clean(config, build)

    if 'generate' in goals:
        print('goal = generate')
        generate(config, src, source, temp, os, operatingSystem, aol, packaging, dependances)

    if 'configure' in goals:
        print('goal = configure')
        configure(config, output, source, dist, operatingSystem, sourcesrc)

    if 'make' in goals:
        print('goal = make')
        make(config, src, source, sourcesrc, output, build, os, operatingSystem, aol)

    if 'dist' in goals:
        print('goal = dist')
        distribution(config, sourcesrc, build, output, dist, os, operatingSystem, aol, packaging)

    if 'deploy' in goals:
        print('goal = deploy')
        deploy(config, build, os, aol, packaging)


    ####################################################################################################
    # Report success
    ####################################################################################################
    print('')
    print('SUCCESS')

