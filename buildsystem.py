

import platform
import os
import subprocess
import sys
import shutil
import gzip
import stat
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
import errno

try:
    import winreg
except ImportError:
    pass


NONE = 0
INFO = 1
VERBOSE = 2
DEBUG = 3

SRC_MAIN_DIR                             = './src/main/'
SRC_MAIN_C_DIR                           = './src/main/c/'
SRC_MAIN_MAKE_DIR                        = './src/main/make/'
SRC_MAIN_ARCHIVE_DIR                     = './src/main/archive/'
                                        
SRC_TEST_DIR                             = './src/test/'
SRC_TEST_C_DIR                           = './src/test/c/'
SRC_TEST_MAKE_DIR                        = './src/test/make/'
                                        
BUILD_DIR                                = './build/'
BUILDTEMP_DIR                            = './build.temp/'
BUILD_SOURCE_DIR                         = './build/source/'
BUILD_SOURCE_MAIN_DIR                    = './build/source/main/'
BUILD_SOURCE_TEST_DIR                    = './build/source/test/'
BUILD_TEMP_DIR                           = './build/temp/'
BUILD_OUTPUT_MAIN_DIR                    = './build/output/main/'
BUILD_OUTPUT_MAIN_METADATA_DIR           = './build/output/main/metadata/'
BUILD_OUTPUT_TEST_DIR                    = './build/output/test/'
BUILD_ARTIFACT_DIR                       = './build/artifact/'
                                       
DIST_DIR                                 = './build/dist/'
DISTTEMP_DIR                             = './build/dist.temp/'
DIST_SHARE_DIR                           = './build/dist/share/'
DIST_BIN_DIR                             = './build/dist/bin/'
DIST_INCLUDE_DIR                         = './build/dist/include/'
DIST_LIB_DIR                             = './build/dist/lib/'
DIST_LIB_SHARED_DIR                      = './build/dist/lib/shared/'
DIST_LIB_STATIC_DIR                      = './build/dist/lib/static/'

INSTALL_DIR_LINUX                        = '/usr/local/'
INSTALL_DIR_WINDOWS                      = 'C:/buildsystem/'
INSTALL_DIR                              = 'undefined'

PACKAGING = 'zip'

####################################################################################################
# Class to Detect and report on the build environment
#
# Windows      x86_64-Windows-vs2015
# Linux        x86_64-linux-gnu
# Cygwin       x86_64-pc-cygwin
# MinGW        i686-w64-mingw32
####################################################################################################

class AOL:

    def __init__(self, config):

        if platform.system().startswith("Linux"):
            self.operatingSystem = 'linux'

        elif platform.system().startswith("CYGWIN"):
            self.operatingSystem = 'cygwin'

        elif platform.system().startswith("Windows"):

            if os.environ.get("MSYSTEM"):
                self.operatingSystem = 'mingw'

            else:
                self.operatingSystem = 'windows'

        else:
            print('The OperatingSystem is not defined')
            sys.exit(1)


        if self.operatingSystem == 'windows':
            if os.path.exists(os.environ['ProgramFiles(x86)']):
                self.architecture = 'x86_64'
            else:
                self.architecture = 'x86'

            if not which('cl.exe'):
                print('The complier CL.EXE is not available')
                sys.exit(1)

            self.linker = getVisualStudioName()

        else:
            if which('gcc'):
                gcc = 'gcc'

            elif which('gcc.exe'):
                gcc = 'gcc.exe'

            else:
                print('The Compiler gcc is not available')
                sys.exit(1)

            p = subprocess.Popen([gcc, '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            returncode = p.wait()

            if returncode == 0:
                lines = stderr.decode('utf-8').splitlines()
                for line in lines:
                    if line.startswith('Target:'):
                        words = line.split()
                        word = words[1]
                        break
    
                string = word.split('-')
                self.architecture = string[0]
                self.operatingSystem = string[1]
                self.linker = string[2]
            else:
                print('Error: Cannot find the version of the compiler')
                print('---------[ stdout ]-----------------------------------------------------------------')
                print(stdout)
                print('---------[ stderr ]-----------------------------------------------------------------')
                print(stderr)
                print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')
                sys.exit(1)


    def __str__(self):
         return self.architecture + '-' + self.operatingSystem + '-' + self.linker


####################################################################################################
# Make a directory
####################################################################################################

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


#
####################################################################################################
# Delete a directory
#
# Windows sometimes defers the delete while it saves metadata.
# So we 'rename' the directory first (which is immediate), then delete the directory.
# This avoids a 'permission' problem when trying to create the directory immediatly afterwards
####################################################################################################

def rmdir(directory, temp):
    if os.path.exists(directory):
        os.rename(directory, temp)
        shutil.rmtree(temp, ignore_errors=True)


####################################################################################################
# Print a password!
####################################################################################################

def passwordToString(text):
    return '*' * len(text)



####################################################################################################
# Replace a specific line in a file
####################################################################################################

def replaceLineInFile(filename, linenumber, text):
    with open(filename, 'r') as file:
        data = file.readlines()

    data[linenumber] = text

    with open(filename, 'w') as file:
        file.writelines( data )


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
            return

    # Safely write the changed content, if found in the file
    with open(filename, 'w') as f:
        s = s.replace(old_string, new_string)
        f.write(s)

#
####################################################################################################
# Check a sub process completes ok          
####################################################################################################

def checkProcessCompletesOk(config, process, message, expectedReturnCodes=[0]):
    stdout, stderr = process.communicate()
    returncode = process.wait()

    ok = True if returncode in expectedReturnCodes else False

    if (not ok):
        print(message)

    if (not ok) or (verbose(config)):
        print('---------[ stdout ]-----------------------------------------------------------------')
        print(stdout.decode('utf-8'))
        print('---------[ stderr ]-----------------------------------------------------------------')
        print(stderr.decode('utf-8'))
        print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

    if (not ok):
        sys.exit(1)


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
                if item.tag == 'password':
                    print('        tag: ' + item.tag + ' : ' + passwordToString(value))
                else:
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
            print('        ' + id + ': ( ' + servers[id]['username'] + ' : ' + passwordToString(servers[id]['password']) + ' )')

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
        print('    password = ' + passwordToString(password))

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
        print('    password = ' + passwordToString(server['password']))

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
    lines.append('  <packaging>' + PACKAGING + '</packaging>\n')
    lines.append('</project>\n')

    buffer = BytesIO()
    for line in lines:
        buffer.write(line.encode('utf-8'))

    return buffer


####################################################################################################
# Upload a file and its md5 and its sha1 to Nexus
####################################################################################################

def uploadArtifact(config, mavenGroupId, mavenArtifactId, version, filename):

    if debug(config):
        print('uploadArtifact:')
        print('    mavenGroupId =', mavenGroupId)
        print('    mavenArtifactId =', mavenArtifactId)
        print('    version =', version)
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
    uploadFileAndHashes(config, file, filePathVersion, fileName, PACKAGING)
    file.close()

    # Upload the pom file
    file = makePom(config, mavenGroupId, mavenArtifactId, version, PACKAGING)

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
# Add Git information to an environment list
####################################################################################################

def getBuildInfo(config, aol, environ):

    if (environ == None):
        environ = {}

    gitStatus = subprocess.check_output("git status", shell=True).decode('utf-8').strip()
    gitOrigin = subprocess.check_output("git config --get remote.origin.url", shell=True).decode('utf-8').strip()
    gitCommit = subprocess.check_output("git rev-parse HEAD", shell=True).decode('utf-8').strip()
    groupId = config["groupId"]
    artifactId = config["artifactId"]


    version = multipleReplace(config["version"], config["properties"])
    time_seconds = datetime.datetime.now()
    time_formatted = '{:%Y-%m-%d %H:%M:%S}'.format(time_seconds)


    if aol.operatingSystem == 'windows':
        args = ['cmd', '/C', 'git', 'status']
    else:
        args = ['git', 'status']

    if verbose(config):
        print('Args = ' + str(args))

    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ)
    stdout, stderr = p.communicate()
    returncode = p.wait()


    directory = BUILD_OUTPUT_MAIN_METADATA_DIR + 'git.status/'
    mkdir_p(directory)

    with open(directory + 'stdout.txt', "w") as text_file:
        text_file.write(stdout.decode('utf-8'))

    with open(directory + 'stderr.txt', "w") as text_file:
        text_file.write(stderr.decode('utf-8'))

    with open(directory + 'exitcode.txt', "w") as text_file:
        text_file.write(str(returncode))





    if aol.operatingSystem == 'windows':
        args = ['cmd', '/C', 'git', 'diff']
    else:
        args = ['git', 'diff']

    if verbose(config):
        print('Args = ' + str(args))

    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ)
    stdout, stderr = p.communicate()
    returncode = p.wait()

    directory = BUILD_OUTPUT_MAIN_METADATA_DIR + 'git.diff/'
    mkdir_p(directory)

    with open(directory + 'stdout.txt', "w") as text_file:
        text_file.write(stdout.decode('utf-8'))

    with open(directory + 'stderr.txt', "w") as text_file:
        text_file.write(stderr.decode('utf-8'))

    with open(directory + 'exitcode.txt', "w") as text_file:
        text_file.write(str(returncode))

    data = {}
    data['git'] = { 'origin' : gitOrigin, 'commit' : gitCommit }
    data['groupId'] = groupId
    data['artifactId'] = artifactId
    data['aol'] = str(aol)
    data['datetime'] = time_formatted
    data['version'] = version

    with open(BUILD_OUTPUT_MAIN_METADATA_DIR + 'info.json', "w") as outfile:
        json.dump(data, outfile, sort_keys = True, indent = 4)

    return environ



####################################################################################################
# Read the "lastUpdated.json" file
####################################################################################################

def readLastUpdatedFile(config, directory):

    if debug(config):
        print('readLastUpdatedFile:')
        print('    directory = ' + directory)

    filepath = directory + '/' + 'lastUpdated.json'

    if not os.path.exists(filepath):
        if verbose(config):
            print('Dependency not found in local repository')
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

    filepath = directory + '/' + 'lastUpdated.json'

    with open(filepath, 'w') as outfile:
        json.dump(data, outfile, indent=4, sort_keys=True, separators=(',', ':'))


####################################################################################################
# Is the package up-to-date
####################################################################################################

def isInstalledPackageAtRequredVersion(config, artifactId, requiredVersion, mavenGroupId, mavenArtifactId):

    packageName = artifactId.split('-')[0]
    print('packageName = ' + packageName)    

    packageInfoFilename = os.path.abspath(INSTALL_DIR + 'share/' + packageName + '/info.json')
    print('packageInfoFilename = ' + packageInfoFilename) 
    
    if not os.path.exists(packageInfoFilename):
        print('packageInfoFilename not found: ' + packageInfoFilename + ' Need to re-install')
        return True

    with open(packageInfoFilename) as data_file:    
        data = json.load(data_file)

    installedVersion = data['version']
    print('installedVersion = ' + installedVersion)
    print('requiredVersion  = ' + requiredVersion)

    if requiredVersion != installedVersion:
        print('Package ' + packageName + ' Not installed at required version. Need to reinstall')
        return True

    print('Package ' + packageName + ' is already installed at right version')
    needToInstall = False

    snap = requiredVersion.endswith('SNAPSHOT')
    if not snap:
        print('Package is not a snapshot. Nothing more to do!')        
        return False

    print('Package is a snapshot. Need to check snapshot is up-to-date')
    
    # Find a repository containing the package
    repositoryUrl = None
    for repository in config['repositories']:
        url = multipleReplace(repository["url"], config["properties"])

        if debug(config):
            print('    repositoryUrl = ' + url)

        info = getSnapshotInfoFromRepositoryMetadata(config, url, mavenGroupId, mavenArtifactId, requiredVersion)
        if info == None:
            if debug(config):
                print('    Snapshot not found in this Repository')
            continue    
            
        print('Found package snapshot ' + packageName + ' in RepositoryUrl: ' + url)
        repositoryUrl = url
        
    buildNumber = info.get('buildNumber')
    print('Current snapshot build number = ' + str(buildNumber))
    
    return True



####################################################################################################
# Is the package up-to-date
####################################################################################################

def packageHasBeenDownloaded(config, artifactId, requiredVersion):

    snap = version.endswith('SNAPSHOT')

    path = mavenGroupId.replace('.', '/') + '/' + mavenArtifactId + '/' + version

    home = expanduser('~')
    localpath = home + '/.m2/repository/' + path
    fileName = mavenArtifactId + '-' + version

    if debug(config):
        print('    fileName = ' + fileName)
        print('    path = ' + path)
        print('    localpath = ' + localpath)

    lastUpdated = readLastUpdatedFile(config, localpath)

    searchRemoteRepositories = False
    if snap:
        searchRemoteRepositories = True

    elif os.path.exists(localpath + '/' + fileName + '.' + PACKAGING):
        searchRemoteRepositories = False
        if verbose(config):
            print('Artifact already exists in local repository')
    else:
        searchRemoteRepositories = True
        if verbose(config):
            print('Artifact not found in local repository')

    return True


####################################################################################################
# Download an artifact
####################################################################################################

def downloadArtifact(config, mavenGroupId, mavenArtifactId, version):

    if debug(config):
        print('downloadArtifact:')
        print('    mavenGroupId = ' + mavenGroupId)
        print('    mavenArtifactId = ' + mavenArtifactId)
        print('    version = ' + version)


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

            localFilenameExpanded = localpath + '/' + fileNameExpanded
            localFilename = localpath + '/' + fileName

            url = repositoryUrl + '/' + path + '/' + fileNameExpanded

            if debug(config):
                print('downloadArtifact(1):')
                print('    localFilenameExpanded = ' + localFilenameExpanded)
                print('    url = ' + url)

            rc = downloadFileAndHashes(config, url + '.' + PACKAGING, localFilename + '.' + PACKAGING)
            if rc != 0:
                if debug(config):
                    print('    Artifact not found in Repository')
                continue

            downloadFileAndHashes(config, url + '.pom', localFilename + '.pom')

            return

        print('Artifact ' + fileName + ' not found in remote repositories')
        sys.exit(99)


####################################################################################################
# Install package
####################################################################################################

def installPackage(config, mavenGroupId, mavenArtifactId, version):

    if debug(config):
        print('installPackage:')
        print('    mavenGroupId = ' + mavenGroupId)
        print('    mavenArtifactId = ' + mavenArtifactId)
        print('    version = ' + version)

    fileName = mavenArtifactId + '-' + version + '.' + PACKAGING

    home = expanduser('~')
    path = mavenGroupId.replace('.', '/') + '/' + mavenArtifactId + '/' + version
    localpath = home + '/.m2/repository/' + path + '/' + fileName

    if debug(config):
        print('installPackage:')
        print('    localpath = ' + localpath)

    with zipfile.ZipFile(localpath, 'r') as z:
        z.extractall(INSTALL_DIR)


####################################################################################################
# Does windows registry key exist
####################################################################################################

def checkWindowsRegistryKey(root, path):
    try:
        registry_key = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
        winreg.CloseKey(registry_key)
        return True
    except WindowsError:
        return False


####################################################################################################
# Get the version of Visual Studio
####################################################################################################

def readWindowsRegistry(root, path, name):
    try:
        registry_key = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
        value, regtype = winreg.QueryValueEx(registry_key, name)
        winreg.CloseKey(registry_key)
        return value
    except WindowsError:
        return None


####################################################################################################
# Get the version of Visual Studio
####################################################################################################
def getVisualStudioName():

    if checkWindowsRegistryKey(winreg.HKEY_CLASSES_ROOT, "VisualStudio.DTE.14.0"):
        return 'vs2015'

    elif checkWindowsRegistryKey(winreg.HKEY_CLASSES_ROOT, "VisualStudio.DTE.13.0"):
        return 'vs2014'

    elif checkWindowsRegistryKey(winreg.HKEY_CLASSES_ROOT, "VisualStudio.DTE.12.0"):
        return 'vs2013'

    elif checkWindowsRegistryKey(winreg.HKEY_CLASSES_ROOT, "VisualStudio.DTE.11.0"):
        return 'vs2012'

    elif checkWindowsRegistryKey(winreg.HKEY_CLASSES_ROOT, "VisualStudio.DTE.10.0"):
        return 'vs2010'

    elif checkWindowsRegistryKey(winreg.HKEY_CLASSES_ROOT, "VisualStudio.DTE.9.0"):
        return 'vs2008'

    elif checkWindowsRegistryKey(winreg.HKEY_CLASSES_ROOT, "VisualStudio.DTE.8.0"):
        return 'vs2005'

    else:
        print('Could not find Visual Studio')
        sys.exit(1)


####################################################################################################
# Clean
####################################################################################################

def defaultClean(config, aol):
    rmdir(BUILD_DIR, BUILDTEMP_DIR)


####################################################################################################
# Clean
####################################################################################################

def defaultGenerate(config, aol):

    try:
        dependencies = config['dependencies']
    except KeyError:
        return


    for dependency in config['dependencies']:
        groupId = dependency.get('groupId')
        artifactId = dependency.get('artifactId')
        requiredVersion = dependency.get('version')
        packaging = dependency.get('packaging', 'zip')

        reposArtifactId = artifactId.replace('-', '/')
        reposArtifactId = reposArtifactId.replace('.', '-')

        mavenGroupId = groupId + '.' + reposArtifactId
        mavenArtifactId = artifactId + '-' + str(aol)

        if info(config):
            print('dependency:')
            print('    groupId = ' + groupId)
            print('    artifactId = ' + artifactId)
            print('    mavenGroupId = ' + mavenGroupId)
            print('    mavenArtifactId = ' + mavenArtifactId)
            print('    requiredVersion = ' + requiredVersion)
            print('    aol = ' + str(aol))

        installedPackageAtRequiredVersion = isInstalledPackageAtRequredVersion(config, artifactId, requiredVersion, mavenGroupId, mavenArtifactId)
        if not installedPackageAtRequiredVersion:

            hasBeenDownloaded = packageHasBeenDownloaded(config, artifactId, requiredVersion)
            if not hasBeenDownloaded:
                downloadArtifact(config, mavenGroupId, mavenArtifactId, requiredVersion)

            installPackage(config, mavenGroupId, mavenArtifactId, requiredVersion)

    print('EXITing ...')
    sys.exit(1)


####################################################################################################
# Configure
####################################################################################################

def defaultConfigure(config, aol):
    pass


####################################################################################################
# Make
####################################################################################################

def defaultCompile(config, aol):
    print('defaultCompile')

    mkdir_p(BUILD_OUTPUT_MAIN_DIR)

    if aol.operatingSystem == 'windows':
        makefile = os.path.relpath(SRC_MAIN_MAKE_DIR, BUILD_OUTPUT_MAIN_DIR) + '\\' + str(aol) + '.makefile'
        env = getBuildInfo(config, aol, os.environ)
        env['BUILD_TYPE'] = 'static'
        env['SOURCE'] = os.path.relpath(SRC_MAIN_C_DIR, BUILD_OUTPUT_MAIN_DIR)
        env['OUTPUT'] = '.'
        p = subprocess.Popen(['make', '-f', makefile, 'clean', 'all'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=BUILD_OUTPUT_MAIN_DIR)
        checkProcessCompletesOk(p, 'Error: Compile failed')


    else:     # Linux or MinGW or CygWin
        p = subprocess.Popen(['make', 'clean', 'all'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=BUILD_SOURCE_MAIN_DIR)
        checkProcessCompletesOk(p, 'Error: Compile failed')


####################################################################################################
# Distribution
####################################################################################################

def defaultDistribution(config, aol):
    pass


####################################################################################################
# Test Compile
####################################################################################################

def defaultTestCompile(config, aol):

    if not os.path.exists(SRC_TEST_DIR):
        if (verbose(config)):
            print('There is no Test Source directory')
        return

    mkdir_p(BUILD_OUTPUT_TEST_DIR)

    if aol.operatingSystem == 'windows':
        makefile = os.path.relpath(SRC_TEST_MAKE_DIR, BUILD_OUTPUT_TEST_DIR) + '\\' + str(aol) + '.makefile'
        source = os.path.relpath(SRC_TEST_C_DIR, BUILD_OUTPUT_TEST_DIR)

        env = os.environ
        env['BUILD_TYPE'] = 'static'
        env['SOURCE'] = source
        env['OUTPUT'] = '.'

        args = ['make', '-f', makefile, 'clean', 'all']

        if (verbose(config)):
            print('Args = ' + str(args))

        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=BUILD_OUTPUT_TEST_DIR)
        stdout, stderr = p.communicate()
        returncode = p.wait()
       
        if (returncode != 0):
            print('Error: Test Compile failed')

        if (returncode != 0) or (verbose(config)):
            print('---------[ stdout ]-----------------------------------------------------------------')
            print(stdout.decode('utf-8'))
            print('---------[ stderr ]-----------------------------------------------------------------')
            print(stderr.decode('utf-8'))
            print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

        if (returncode != 0):
            sys.exit(1)


    else:     # Linux or MinGW or CygWin
        makefile = os.path.relpath(SRC_TEST_MAKE_DIR, BUILD_OUTPUT_TEST_DIR) + '\\' + str(aol) + '.makefile'
        source = os.path.relpath(SRC_TEST_C_DIR, BUILD_OUTPUT_TEST_DIR)

        env = os.environ
        env['BUILD_TYPE'] = 'normal'
        env['SOURCE'] = source
        env['OUTPUT'] = '.'

        args = ['make', '-f', makefile, 'clean', 'all']

        if (verbose(config)):
            print('Args = ' + str(args))

        p = subprocess.Popen(['make', '-f', makefile, 'clean', 'all'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=BUILD_OUTPUT_TEST_DIR)
        stdout, stderr = p.communicate()
        returncode = p.wait()
       
        if (returncode != 0):
            print('Error: Test Compile failed')

        if (returncode != 0) or (verbose(config)):
            print('---------[ stdout ]-----------------------------------------------------------------')
            print(stdout.decode('utf-8'))
            print('---------[ stderr ]-----------------------------------------------------------------')
            print(stderr.decode('utf-8'))
            print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

        if (returncode != 0):
            sys.exit(1)


####################################################################################################
# Test
####################################################################################################

def defaultTest(config, aol):
    print('defaultTest')

    if not os.path.exists(BUILD_OUTPUT_TEST_DIR):
        if (verbose(config)):
            print('There is no Test Output directory')
        return

    testExecutables = []
    if aol.operatingSystem == 'windows':
        for filename in glob.iglob(BUILD_OUTPUT_TEST_DIR + '**/*.exe', recursive=True):
            testExecutables.append(filename)

        source = BUILD_OUTPUT_MAIN_DIR + '**/*.dll'
        for file in glob.iglob(source, recursive=True):
            fileName = os.path.basename(file)
            parentDir = os.path.dirname(file)
            parentName = os.path.basename(parentDir)
            parentParentDir = os.path.dirname(parentDir)
            parentParentName = os.path.basename(parentParentDir)
            destination = str(parentParentDir) + '/' + fileName
            destination = BUILD_OUTPUT_TEST_DIR + parentParentName + '/' + fileName
            shutil.copy2(file, destination)

    else:
        executable = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
        for filename in glob.iglob(BUILD_OUTPUT_TEST_DIR + '**/*'):
            if os.path.isfile(filename):
                st = os.stat(filename)
                mode = st.st_mode
                if mode & executable:
                    testExecutables.append(filename)

    if len(testExecutables) == 0:
        print('Error: No tests were found under: ' + BUILD_OUTPUT_TEST_DIR)
        sys.exit(1)

    if (verbose(config)):
        print('Running ' + str(len(testExecutables)) + ' Tests')

    for file in testExecutables:

        if (verbose(config)):
            print('    Running: ' + file)
            print('    Working Directory = ' + BUILD_OUTPUT_TEST_DIR)

        args = [os.path.abspath(file)]

        if verbose(config):
            print('Args = ' + str(args))

        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=BUILD_OUTPUT_TEST_DIR)
        stdout, stderr = p.communicate()
        returncode = p.wait()
       
        if (returncode != 0):
            print('Error: test ' + file + ' failed')

        if (returncode != 0) or (verbose(config)):
            print('---------[ stdout ]-----------------------------------------------------------------')
            print(stdout.decode('utf-8'))
            print('---------[ stderr ]-----------------------------------------------------------------')
            print(stderr.decode('utf-8'))
            print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

        if (returncode != 0):
            sys.exit(1)


####################################################################################################
# Deploy
####################################################################################################

def defaultDeploy(config, aol):

    groupId = config["groupId"]
    artifactId = config["artifactId"]
    version = multipleReplace(config["version"], config["properties"])

    reposArtifactId = artifactId.replace('-', '/')
    reposArtifactId = reposArtifactId.replace('.', '-')

    mavenGroupId = groupId + '.' + reposArtifactId
    mavenArtifactId = artifactId + '-' + str(aol)

    filename = BUILD_ARTIFACT_DIR + mavenArtifactId + '.' + PACKAGING

    if debug(config):
        print('main: deploy')
        print('    groupId = ' + groupId)
        print('    artifactId = ' + artifactId)
        print('    mavenGroupId = ' + mavenGroupId)
        print('    mavenArtifactId = ' + mavenArtifactId)
        print('    aol = ' + str(aol))
        print('    version = ' + version)
        print('    filename = ' + filename)

    uploadArtifact(config, mavenGroupId, mavenArtifactId, version, filename)


####################################################################################################
# Main Routine
####################################################################################################

def main(clean=None, generate=None, configure=None, compile=None, distribution=None, testCompile=None, test=None, deploy=None):

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
        goals = ['clean', 'generate', 'configure', 'compile', 'distribution', 'testCompile', 'test', 'deploy']
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
    # Init
    ####################################################################################################

    aol = AOL(config)

    global INSTALL_DIR
    if aol.operatingSystem == 'windows':
        INSTALL_DIR = INSTALL_DIR_WINDOWS 
    else:
        INSTALL_DIR = INSTALL_DIR_LINUX 

    mkdir_p(INSTALL_DIR)

    ####################################################################################################
    # Call the build processes
    ####################################################################################################

    if 'clean' in goals:
        print('goal = clean')
        if clean == None:
            defaultClean(config, aol)
        else:
            clean(config, aol)

    if 'generate' in goals:
        print('goal = generate')
        if generate == None:
            defaultGenerate(config, aol)
        else:
            generate(config, aol)

    if 'configure' in goals:
        print('goal = configure')
        if configure == None:
            defaultConfigure(config, aol)
        else:
            configure(config, aol)

    if 'compile' in goals:
        print('goal = compile')
        if compile == None:
            defaultCompile(config, aol)
        else:
            compile(config, aol)

    if 'distribution' in goals:
        print('goal = distribution')
        if distribution == None:
            defaultDistribution(config, aol)
        else:
            distribution(config, aol)

    if 'testCompile' in goals:
        print('goal = test-compile')
        if testCompile == None:
            clean = defaultTestCompile(config, aol)
        else:
            testCompile(config, aol)

    if 'test' in goals:
        print('goal = test')
        if test == None:
            clean = defaultTest(config, aol)
        else:
            test(config, aol)

    if 'deploy' in goals:
        print('goal = deploy')
        if deploy == None:
            clean = defaultDeploy(config, aol)
        else:
            deploy(config, aol)


    ####################################################################################################
    # Report success
    ####################################################################################################
    print('')
    print('SUCCESS')





