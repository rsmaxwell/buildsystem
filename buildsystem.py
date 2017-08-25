
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
import fnmatch
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
DEBUG2 = 4

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
BUILD_OUTPUT_TEST_DIR                    = './build/output/test/'
BUILD_ARTIFACT_DIR                       = './build/artifact/'

DIST_DIR                                 = './build/dist/'
DISTTEMP_DIR                             = './build/dist.temp/'
DIST_PACKAGES_DIR                        = './build/dist/packages/'
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

    def __init__(self):

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
# Get the Install dir for MinGW
####################################################################################################

def unzip(config, aol, zipFile, extractDir):

    if debug2(config):
        print('unzip:')
        print('    zipFile = ' + zipFile)
        print('    extractDir = ' + extractDir)

    if not aol.linker.startswith('mingw'):
        with zipfile.ZipFile(zipFile, 'r') as z:
            z.extractall(extractDir)
    else:
        args = ['bash', '-c', 'unzip -o ' + zipFile + ' -d ' + extractDir]

        if debug(config):
            print('Args = ' + str(args))

        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        returncode = p.wait()

        if (returncode != 0):
            print('Error: subprocess.Popen failed')

        if (returncode != 0) or (debug(config)):
            print('---------[ stdout ]-----------------------------------------------------------------')
            print(stdout.decode('utf-8'))
            print('---------[ stderr ]-----------------------------------------------------------------')
            print(stderr.decode('utf-8'))
            print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

        if (returncode != 0):
            sys.exit(1)





####################################################################################################
# Unzip an archive as superuser
####################################################################################################

def superuser_unzip(config, aol, zipFile, extractDir):

    if debug2(config):
        print('superuser_unzip:')
        print('    zipFile = ' + zipFile)
        print('    extractDir = ' + extractDir)

    if aol.operatingSystem == 'windows':
        args = ['cmd', '/C', 'unzip -o ' + zipFile + ' -d ' + extractDir]
    else:
        args = ['sudo', 'unzip -o ' + zipFile + ' -d ' + extractDir]

    if debug(config):
        print('args = ' + str(args))

    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    returncode = p.wait()

    if (returncode != 0):
        print('Error: subprocess.Popen failed')

    if (returncode != 0) or (debug(config)):
        print('args = ' + str(args))
        print('---------[ stdout ]-----------------------------------------------------------------')
        print(stdout.decode('utf-8'))
        print('---------[ stderr ]-----------------------------------------------------------------')
        print(stderr.decode('utf-8'))
        print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

    if (returncode != 0):
        sys.exit(1)




####################################################################################################
# Test if a file exists
####################################################################################################
def exists(config, aol, filename):

    if debug2(config):
        print('exists:')
        print('    filename = ' + filename)

    if not aol.linker.startswith('mingw'):
        return os.path.exists(filename)
    else:
        args = ['bash', '-c', 'ls ' + filename]

        if debug(config):
            print('Args = ' + str(args))

        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        returncode = p.wait()

        if debug2(config):
            print('---------[ stdout ]-----------------------------------------------------------------')
            print(stdout.decode('utf-8'))
            print('---------[ stderr ]-----------------------------------------------------------------')
            print(stderr.decode('utf-8'))
            print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

        return (returncode == 0)

####################################################################################################
# Make a directory as superuser
####################################################################################################

def superuser_mkdir(config, aol, path):

    if debug2(config):
        print('superuser_mkdir:')
        print('    path = ' + path)

    if aol.operatingSystem == 'windows':
        windowsPath = os.path.abspath(path)
        args = ['cmd', '/C', 'mkdir ' + windowsPath]
    else:
        args = ['sudo', 'bash', '-c', 'mkdir -p ' + path]

    if debug(config):
        print('args = ' + str(args))

    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    returncode = p.wait()

    if (returncode != 0):
        print('Error: subprocess.Popen failed')

    if (returncode != 0) or (debug(config)):
        print('---------[ stdout ]-----------------------------------------------------------------')
        print(stdout.decode('utf-8'))
        print('---------[ stderr ]-----------------------------------------------------------------')
        print(stderr.decode('utf-8'))
        print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

    if (returncode != 0):
        sys.exit(1)


####################################################################################################
# Make a directory
####################################################################################################

def mkdir(config, aol, path):

    if debug2(config):
        print('mkdir:')
        print('    path = ' + path)

    if not aol.linker.startswith('mingw'):

        if os.path.isdir(path):
            return 0

        try:
            os.makedirs(path)
        except OSError as exc:  # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else:
                print('mkdir:  Exception = ' + str(exc))
                print('        errno = ' + str(exc.errno))
                sys.exit(1)

    else:
        args = ['bash', '-c', 'mkdir -p ' + path]

        if debug(config):
            print('args = ' + str(args))

        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        returncode = p.wait()

        if (returncode != 0):
            print('Error: subprocess.Popen failed')

        if (returncode != 0) or (debug(config)):
            print('---------[ stdout ]-----------------------------------------------------------------')
            print(stdout.decode('utf-8'))
            print('---------[ stderr ]-----------------------------------------------------------------')
            print(stderr.decode('utf-8'))
            print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

        if (returncode != 0):
            sys.exit(1)


####################################################################################################
# Delete a directory
#
# Windows sometimes defers the delete while it saves metadata.
# So we 'rename' the directory first (which is immediate), then delete the directory.
# This avoids a 'permission' problem when trying to create the directory immediately afterwards
####################################################################################################

def rmdir(config, aol, directory, temp):

    if debug2(config):
        print('rmdir:')
        print('    directory = ' + directory)
        print('    temp = ' + temp)

    if not aol.linker.startswith('mingw'):
        if os.path.exists(directory):
            os.rename(directory, temp)
            shutil.rmtree(temp, ignore_errors=True)
    else:
        args = ['bash', '-c', 'rm -rf ' + directory]

        if debug(config):
            print('Args = ' + str(args))

        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        returncode = p.wait()

        if (returncode != 0):
            print('Error: subprocess.Popen failed')

        if (returncode != 0) or (debug(config)):
            print('---------[ stdout ]-----------------------------------------------------------------')
            print(stdout.decode('utf-8'))
            print('---------[ stderr ]-----------------------------------------------------------------')
            print(stderr.decode('utf-8'))
            print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

        if (returncode != 0):
            sys.exit(1)


####################################################################################################
# Expand user home
####################################################################################################
def myExpandUserHome(config, aol):

    if debug2(config):
        print('myExpandUserHome:')

    if not aol.linker.startswith('mingw'):
        return expanduser('~')
    else:
        args = ['bash', '-c', 'echo $HOME']

        if debug(config):
            print('Args = ' + str(args))

        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        returncode = p.wait()

        if (returncode != 0):
            print('Error: subprocess.Popen failed')

        if (returncode != 0) or (debug(config)):
            print('---------[ stdout ]-----------------------------------------------------------------')
            print(stdout.decode('utf-8'))
            print('---------[ stderr ]-----------------------------------------------------------------')
            print(stderr.decode('utf-8'))
            print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

        if (returncode != 0):
            sys.exit(1)

        result = stdout.decode('utf-8').strip()
        print('myExpandUserHome = ' + result)
        return result


####################################################################################################
# MingW path
####################################################################################################
def mingwToNativePath(config, aol, pathname):

    if debug(config):
        print('mingwToNativePath:')

    fn = os.path.basename(pathname)
    dn = os.path.dirname(pathname)

    args = ['bash', '-c', "{ cd " + dn + " && pwd -W; }"]

    if debug(config):
        print('Args = ' + str(args))
        print('Args[2] = ' + args[2])

    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    returncode = p.wait()

    if (returncode != 0):
        print('Error: subprocess.Popen failed')

    if (returncode != 0) or (debug(config)):
        print('---------[ stdout ]-----------------------------------------------------------------')
        print(stdout.decode('utf-8'))
        print('---------[ stderr ]-----------------------------------------------------------------')
        print(stderr.decode('utf-8'))
        print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

    if (returncode != 0):
        sys.exit(1)

    result = stdout.decode('utf-8').strip() + '/' + fn
    result = result .replace('/', '\\')
    return result


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

def debug2(config):
    return config['level'] >= DEBUG2

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
# Get the Root directory
####################################################################################################
def get_sys_exec_root_or_drive():
    path = sys.executable
    while os.path.split(path)[1]:
        path = os.path.split(path)[0]
    return path


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

def parseSnapshotMetadata(config, content):

    if debug(config):
        print("parseSnapshotMetadata:")

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

def getSnapshotMetadataFromRemoteRepository(config, repositoryUrl, mavenGroupId, mavenArtifactId, version):

    snapshotInfo = None

    if debug(config):
        print('getSnapshotMetadataFromRemoteRepository:')
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

        snapshotInfo = parseSnapshotMetadata(config, r.text)

    elif r.status_code == 404: # http.HTTPStatus.NOT_FOUND.value
        if debug(config):
            print('    Artifact not found in Remote Repository')

    else:
        print('Unexpected Http response ' + str(r.status_code) + ' when getting: maven-metadata.xml')
        print('    metadataUrl: ' + metadataUrl)
        content = r.raw.read().decode('utf-8')
        print('Content =', content)
        sys.exit(99)

    return snapshotInfo


####################################################################################################
# Read the metadata and return the version
####################################################################################################

def getSnapshotInfoFromDistributionMetadata(config, mavenGroupId, mavenArtifactId, version):

    if debug(config):
        print('getSnapshotInfoFromDistributionMetadata(1):')
        print('    mavenGroupId = ' + mavenGroupId)
        print('    mavenArtifactId = ' + mavenArtifactId)
        print('    version = ' + version)

    deployment = config['distributionManagement']['repository']['deployment']
    repositoryUrl = multipleReplace(deployment['url'], config['properties'])

    return getSnapshotMetadataFromRemoteRepository(config, repositoryUrl, mavenGroupId, mavenArtifactId, version)



####################################################################################################
# Get the server credentials from the maven xml settings file
####################################################################################################

def getServersConfigurationFromSettingsFile(config, aol):

    if verbose(config):
        print('getServersConfigurationFromSettingsFile:')

    home = myExpandUserHome(config, aol)
    settingsfile = home + '/.m2/settings.xml'

    if verbose(config):
        print('settingsfile  = ' + settingsfile)

    if not exists(config, aol, settingsfile):
        print('Settings file NOT found = ' + settingsfile)
        sys.exit(3)

    if aol.linker.startswith('ming'):
        settingsfile2 = mingwToNativePath(config, aol, settingsfile)
    else:
        settingsfile2 = settingsfile

    if verbose(config):
        print('settingsfile2 = ' + settingsfile2)

    # instead of ET.fromstring(xml)
    it = ET.iterparse(settingsfile2)
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

    if debug(config):
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

    if debug(config):
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

    if statusCode > 400:
        print('    statusCode = ' + str(statusCode) + ' : ' + http.client.responses[statusCode])
        sys.exit(3)

    if debug(config):
        print('    statusCode = ' + str(statusCode) + ' : ' + http.client.responses[statusCode])

    return statusCode


####################################################################################################
# Upload a stream to a URL
####################################################################################################

def uploadFile(config, file, repositoryID, url):

    if debug(config):
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

    if debug(config):
        print('    statusCode = ' + str(statusCode) + ' : ' + http.client.responses[statusCode])

    if statusCode >= 400:
        sys.exit(3)

    return statusCode


####################################################################################################
# Upload a string
####################################################################################################

def uploadString(config, string, repositoryID, url):

    if debug(config):
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

    if debug(config):
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

    if verbose(config):
        data = {}
        data['mavenGroupId'] = mavenGroupId
        data['mavenArtifactId'] = mavenArtifactId
        data['version'] = version
        print('Uploading artifact')
        print(json.dumps(data, sort_keys = True, indent = 4))

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
        print('uploadArtifact(3): ')
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

def writeCompileTimeMetadata(config, aol):

    if verbose(config):
        print('writeCompileTimeMetadata')

    artifactId = config["artifactId"]
    packageName = artifactId.split('-')[0]
    packageDir = DIST_PACKAGES_DIR + packageName + '/'

    if verbose(config):
        print('packageDir = ' + packageDir)

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


    directory = packageDir + 'git.status/'
    mkdir(config, aol, directory)

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

    directory = packageDir + 'git.diff/'
    mkdir(config, aol, directory)

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

    with open(packageDir + 'metadata.json', "w") as outfile:
        json.dump(data, outfile, sort_keys = True, indent = 4)



####################################################################################################
#
####################################################################################################
def getPackageName(artifactId):
    return artifactId.split('-')[0]


####################################################################################################
#
####################################################################################################
def isSnapshot(version):
    return version.endswith('SNAPSHOT')


####################################################################################################
# Read the "lastUpdated.json" file
####################################################################################################

def readLocalRepositoryPackageMetadata(config, directory):

    if debug(config):
        print('readLocalRepositoryPackageMetadata:')

    filepath = directory + '/' + 'metadata.json'

    if debug(config):
        print('    filepath  = ' + filepath)

    if not os.path.exists(filepath):
        if verbose(config):
            print('Dependency not found in local repository')
            print(filepath)
        return None

    metadata = {}
    with open(filepath) as file:
        metadata.update(json.load(file))

    return metadata


####################################################################################################
# Write the "lastUpdated.json" file to the local directory
####################################################################################################

def writeLocalRepositoryArtifactMetadata(config, localRepositoryPath, metadata):

    if debug(config):
        print('writeLocalRepositoryArtifactMetadata:')
        print('    localRepositoryPath = ' + localRepositoryPath)

    if not os.path.exists(localRepositoryPath):
        os.makedirs(localRepositoryPath)

    filepath = localRepositoryPath + '/' + 'metadata.json'

    with open(filepath, 'w') as outfile:
        json.dump(metadata, outfile, sort_keys=True, indent=4)

    if verbose(config):
        print('Updating local repository metadata')
    if debug(config):
        print(json.dumps(metadata, sort_keys = True, indent = 4))


####################################################################################################
#
####################################################################################################

def checkUpdatePolicyInterval(config, intervalMinutes, lastCheckedTimestamp):

    interval = datetime.timedelta(minutes=intervalMinutes)
    lastChecked = datetime.datetime.strptime(lastCheckedTimestamp, '%Y%m%d.%H%M%S')
    now = datetime.datetime.now()

    if debug(config):
        print('    intervalMinutes = ' + str(intervalMinutes))
        print('    interval        = ' + str(interval))
        print('    lastChecked     = ' + str(lastChecked))
        print('    lastChecked + interval = ' + str(lastChecked + interval))
        print('    now                    = ' + str(now))

    if now > lastChecked + interval:
        return True

    return False


####################################################################################################
#
####################################################################################################

def checkUpdatePolicy(config, repository, lastChecked):

    if debug(config):
        print('checkUpdatePolicy:')
        print('    repository = ' + repository['url'])
        print('    lastChecked = ' + lastChecked)

    checkRemoteRepository = False
    key = 'updatePolicy'
    if key in repository:
        updatePolicy = repository[key]

        if updatePolicy == 'daily':
            checkRemoteRepository = False

        elif updatePolicy == 'always':
            checkRemoteRepository = True

        elif updatePolicy == 'never':
            checkRemoteRepository = False

        else:
            match = re.match('interval:([0-9]{1,10})', updatePolicy)
            if match:
                string = match.group(1)
                interval = int(string)
                checkRemoteRepository = checkUpdatePolicyInterval(config, interval, lastChecked)

            else:
                print('Unexpected value in the repository updatePolicy: ' + updatePolicy)
                print('Repository: ')
                print(json.dumps(repository, sort_keys = True, indent = 4))
                sys.exit(2)

    else:
        interval = 24 * 60    # 1 day in minutes
        checkRemoteRepository = checkUpdatePolicyInterval(config, interval, lastChecked)

    return checkRemoteRepository



####################################################################################################
# getVersion package version in remote repository
####################################################################################################
def getRemotePackageVersionFromRemoteMetadata(config, artifactId, requiredVersion, mavenArtifactId, remoteMetadata):

    if isSnapshot(requiredVersion):
        key = 'timestamp'
        if not key in remoteMetadata:
            print('Error: The localMetadata for ' + packageName + ' does not contain the key "' + key + '"')
            print('localRepositoryPath = ' + localRepositoryPath)
            print(json.dumps(remoteMetadata, sort_keys=True, indent=4))
            sys.exit(3)

        key = 'buildNumber'
        if not key in remoteMetadata:
            print('Error: The localMetadata for ' + packageName + ' does not contain the key "' + key + '"')
            print('localRepositoryPath = ' + localRepositoryPath)
            print(json.dumps(remoteMetadata, sort_keys=True, indent=4))
            sys.exit(3)

        remotePackageVersion = mavenArtifactId + '-' + requiredVersion.replace('SNAPSHOT', remoteMetadata.get('timestamp')) + '-' + str(remoteMetadata.get('buildNumber'))
    else:
        remotePackageVersion = mavenArtifactId + '-' + requiredVersion

    return remotePackageVersion


####################################################################################################
# getVersion package version in remote repository
####################################################################################################
def getRemotePackageVersion(config, artifactId, requiredVersion, mavenGroupId, mavenArtifactId, localRepositoryPath):

    if debug(config):
        print('getRemotePackageVersion:')

    packageName = getPackageName(artifactId)

    #---------------------------------------------------------------------------
    # Find a remote repository containing the package
    #---------------------------------------------------------------------------
    localMetadata = readLocalRepositoryPackageMetadata(config, localRepositoryPath)
    lastChecked = localMetadata['lastChecked']

    found = None
    for repository in config['repositories']:

        repositoryUrl = multipleReplace(repository['url'], config['properties'])

        if verbose(config):
            print('Repository: ' + repositoryUrl)
        elif debug(config):
            print('Repository:')
            print(json.dumps(repository, sort_keys = True, indent = 4))

        checkRemoteRepository = checkUpdatePolicy(config, repository, lastChecked)
        if not checkRemoteRepository:
            if verbose(config):
                print('Skipping repository')
            continue

        if debug(config):
            print('Checking repository')

        remoteMetadata = getSnapshotMetadataFromRemoteRepository(config, repositoryUrl, mavenGroupId, mavenArtifactId, requiredVersion)
        if remoteMetadata:
            found = repository
            break

        if verbose(config):
            print('Package not found in this Repository')

    if not found:
        print('Package ' + packageName + ' not found in any repository')
        return (None, None)

    #---------------------------------------------------------------------------
    # Lookup the packageVersion
    #---------------------------------------------------------------------------
    if verbose(config):
        print('Found package snapshot ' + packageName + ' in repository: ' + repository['url'])
    if debug(config):
        print('Package metadata for the remote repository')
        print(json.dumps(remoteMetadata, sort_keys = True, indent = 4))

    remotePackageVersion = getRemotePackageVersionFromRemoteMetadata(config, artifactId, requiredVersion, mavenArtifactId, remoteMetadata)

    if verbose(config):
        print('remotePackageVersion = ' + remotePackageVersion)

    localMetadata['lastChecked'] = '{:%Y%m%d.%H%M%S}'.format(datetime.datetime.now())
    writeLocalRepositoryArtifactMetadata(config, localRepositoryPath, localMetadata)

    return (remotePackageVersion, repository)


####################################################################################################
# Is the installed package up-to-date compared to the remote repository
####################################################################################################

def getLocalPackageVersion(config, artifactId, requiredVersion, mavenGroupId, mavenArtifactId, localRepositoryPath):

    if debug(config):
        print('getLocalRepositoryVersion:')

    packageName = getPackageName(artifactId)

    localMetadata = readLocalRepositoryPackageMetadata(config, localRepositoryPath)
    if localMetadata is None:
        if verbose(config):
            print('The package was not found in the local repository. Update needed')
        return (True, None)

    if verbose(config):
        print('localRepositoryPath = ' + localRepositoryPath)
        print('Package metadata for the local repository')
        print(json.dumps(localMetadata, sort_keys = True, indent = 4))

    key = 'originalFilename'
    if key in localMetadata:
        localPackageVersion = localMetadata[key]
    else:
        print('Error: The localMetadata for ' + packageName + ' does not contain the key "' + key + '"')
        print('localRepositoryPath = ' + localRepositoryPath)
        print(json.dumps(localMetadata, sort_keys=True, indent=4))
        sys.exit(3)

    return localPackageVersion


####################################################################################################
# Is the installed package up-to-date compared to the remote repository
####################################################################################################

def checkVersionOfLocalPackage(config, artifactId, requiredVersion, mavenGroupId, mavenArtifactId, localRepositoryPath):

    if debug(config):
        print('checkVersionOfLocalPackage:')

    packageName = getPackageName(artifactId)

    localMetadata = readLocalRepositoryPackageMetadata(config, localRepositoryPath)
    if localMetadata is None:
        if verbose(config):
            print('Package ' + packageName + ' not found in local repository. Update needed')
        return (True, None)

    if verbose(config):
        print('Package ' + packageName + ' in local repository is at the required version')

    if not isSnapshot(requiredVersion):
        return (False, None)  # Nothing to do!

    #---------------------------------------------------------------------------
    # Check the snapshot is up-to-date
    #---------------------------------------------------------------------------
    if verbose(config):
        print('Need to check the snapshot in the local repository is up-to-date')

    key = 'originalFilename'
    if key in localMetadata:
        localPackageVersion = localMetadata[key]
    else:
        print('Error: The localMetadata for ' + packageName + ' does not contain the key "' + key + '"')
        print('localRepositoryPath = ' + localRepositoryPath)
        print(json.dumps(localMetadata, sort_keys=True, indent=4))
        sys.exit(3)

    if verbose(config):
        print('localPackageVersion = ' + localPackageVersion)

    remotePackageVersion, repository = getRemotePackageVersion(config, artifactId, requiredVersion, mavenGroupId, mavenArtifactId, localRepositoryPath)
    if remotePackageVersion == None:
        return (False, repository)  # Nothing to do!
    elif localPackageVersion == remotePackageVersion:
        return (False, repository)  # Nothing to do!
    else:
        return (True, repository)


####################################################################################################
# Is the installed package up-to-date compared to the remote repository
####################################################################################################

def checkVersionOfInstalledPackage(config, aol, artifactId, requiredVersion, mavenGroupId, mavenArtifactId, localRepositoryPath):

    if debug(config):
        print('checkVersionOfInstalledPackage:')

    packageName = getPackageName(artifactId)

    #---------------------------------------------------------------------------
    # Is the version of the installed package the same as the requiredVersion
    #---------------------------------------------------------------------------
    packageInfoFilename = INSTALL_DIR + 'packages/' + packageName + '/metadata.json'
    if verbose(config):
        print('packageInfoFilename = ' + packageInfoFilename)

    if not exists(config, aol, packageInfoFilename):
        if verbose(config):
            print('Package ' + packageInfoFilename + ' not installed. Need to re-install')
        updateNeeded, repository = checkVersionOfLocalPackage(config, artifactId, requiredVersion, mavenGroupId, mavenArtifactId, localRepositoryPath)
        return (updateNeeded, True, repository)

    if aol.operatingSystem == 'ming':
        packageInfoFilename2 = mingwToNativePath(config, aol, packageInfoFilename)
    else:
        packageInfoFilename2 = os.path.abspath(packageInfoFilename)

    if verbose(config):
        print('packageInfoFilename2 = ' + packageInfoFilename2)

    with open(packageInfoFilename2) as file:
        installedMetadata = json.load(file)

    if debug(config):
        print('installedMetadata:')
        print(json.dumps(installedMetadata, sort_keys=True, indent=4))

    installedVersion = installedMetadata['version']
    if verbose(config):
        print('installedVersion = ' + installedVersion)
        print('requiredVersion  = ' + requiredVersion)

    if requiredVersion != installedVersion:
        if verbose(config):
            print('Package ' + packageName + ' not installed at required version. Need to reinstall')
        updateNeeded, repository = checkVersionOfLocalPackage(config, artifactId, requiredVersion, mavenGroupId, mavenArtifactId, localRepositoryPath)
        return (updateNeeded, True, repository)

    if verbose(config):
        print('Package ' + packageName + ' is installed at requiredVersion')

    if not isSnapshot(requiredVersion):
        return (False, False, repository)  # Nothing to do!

    #---------------------------------------------------------------------------
    # Check the snapshot is up-to-date
    #---------------------------------------------------------------------------
    if verbose(config):
        print('Need to check the snapshot is up-to-date')

    key = 'originalFilename'
    if key in installedMetadata:
        installedPackageVersion = installedMetadata['originalFilename']
    else:
        print('The installed metadata for ' + packageName + ' does not contain the key "' + key + '"')
        print('packageInfoFilename  = ' + packageInfoFilename)
        print('packageInfoFilename2 = ' + packageInfoFilename2)
        print(json.dumps(installedMetadata, sort_keys=True, indent=4))
        print('The package needs re-installing')
        return (False, True, None)

    remotePackageVersion, repository = getRemotePackageVersion(config, artifactId, requiredVersion, mavenGroupId, mavenArtifactId, localRepositoryPath)
    if remotePackageVersion == None:
        if verbose(config):
            print('The package is up-to-date')
        return (False, False, repository)   # Nothing to do!
    elif installedPackageVersion == remotePackageVersion:
        if verbose(config):
            print('The package is up-to-date')
        return (False, False, repository)   # Nothing to do!
    else:
        localPackageVersion = getLocalPackageVersion(config, artifactId, requiredVersion, mavenGroupId, mavenArtifactId, localRepositoryPath)
        if localPackageVersion == remotePackageVersion:
            print('The package needs re-installing')
            return (False, True, repository)
        else:
            print('The package needs downloading and re-installing')
            return (True, True, repository)


####################################################################################################
# Download an artifact
####################################################################################################

def downloadArtifactFromRepository(config, repository, localRepositoryPath, fileName, mavenGroupId, mavenArtifactId, version, isSnapshot):

    if debug(config):
        print('downloadArtifactFromRepository:')


    repositoryUrl = multipleReplace(repository["url"], config["properties"])

    if debug(config):
        print('    repositoryUrl = ' + repositoryUrl)

    if isSnapshot:
        remoteMetadata = getSnapshotMetadataFromRemoteRepository(config, repositoryUrl, mavenGroupId, mavenArtifactId, version)
        if remoteMetadata == None:
            print('Artifact ' + fileName + ' not found in remote repository')
            return False
        else:
            if debug(config):
                print('Remote repository metadata')
                print(json.dumps(remoteMetadata, sort_keys = True, indent = 4))

        fileNameExpanded = mavenArtifactId + '-' + version.replace('SNAPSHOT', remoteMetadata.get('timestamp')) + '-' + str(remoteMetadata.get('buildNumber'))
    else:
        fileNameExpanded = mavenArtifactId + '-' + version

    localFilenameExpanded = localRepositoryPath + '/' + fileNameExpanded
    localFilename = localRepositoryPath + '/' + fileName

    path = mavenGroupId.replace('.', '/') + '/' + mavenArtifactId + '/' + version

    url = repositoryUrl + '/' + path + '/' + fileNameExpanded

    if debug(config):
        print('downloadArtifactFromRepository:')
        print('    localFilenameExpanded = ' + localFilenameExpanded)
        print('    url = ' + url)

    rc = downloadFileAndHashes(config, url + '.' + PACKAGING, localFilename + '.' + PACKAGING)
    if rc != 0:
        print('Artifact ' + fileName + ' not found in remote repositories')
        sys.exit(99)

    rc = downloadFileAndHashes(config, url + '.pom', localFilename + '.pom')
    if rc != 0:
        print('Error downloading ' + localFilename + '.pom from remote repository')
        sys.exit(99)

    localMetadata = {}
    localMetadata['originalFilename'] = fileNameExpanded
    localMetadata['lastChecked'] = '{:%Y%m%d.%H%M%S}'.format(datetime.datetime.now())
    writeLocalRepositoryArtifactMetadata(config, localRepositoryPath, localMetadata)

    return True


####################################################################################################
# Download an artifact
####################################################################################################

def downloadArtifact(config, repository, localRepositoryPath, fileName, mavenGroupId, mavenArtifactId, version, isSnapshot):

    if debug(config):
        print('downloadArtifact:')
        print('    repository = ' + str(repository))
        print('    localRepositoryPath = ' + localRepositoryPath)
        print('    mavenGroupId = ' + mavenGroupId)
        print('    mavenArtifactId = ' + mavenArtifactId)
        print('    version = ' + version)
        print('    isSnapshot = ' + str(isSnapshot))

    if repository:
        if verbose(config):
            print('Looking for artifact remote repository: ' + str(repository))

        found = downloadArtifactFromRepository(config, repository, localRepositoryPath, fileName, mavenGroupId, mavenArtifactId, version, isSnapshot)

    else:
        if verbose(config):
            print('Looking for artifact in remote repositories')

        for repository in config['repositories']:
            found = downloadArtifactFromRepository(config, repository, localRepositoryPath, fileName, mavenGroupId, mavenArtifactId, version, isSnapshot)
            if found:
                break

    if not found:
        print('Artifact ' + fileName + ' not found in remote repositories')
        sys.exit(99)

    return repository

#
####################################################################################################
# InInstall package
####################################################################################################

def unInstallPackage(config, aol, artifactId, mavenGroupId, mavenArtifactId, requiredVersion, localRepositoryPath):

    if debug(config):
        print('unInstallPackage:')
        print('    artifactId = ' + artifactId)
        print('    mavenGroupId = ' + mavenGroupId)
        print('    mavenArtifactId = ' + mavenArtifactId)
        print('    requiredVersion = ' + requiredVersion)
        print('    localRepositoryPath = ' + localRepositoryPath)

    packageName = getPackageName(artifactId)




    packageDir = INSTALL_DIR + 'packages/' + packageName

    if os.path.exists(packageDir):
        print('packageDir = ' + packageDir + ' already exists')
    else:
        print('Creating packageDir = ' + packageDir)
        superuser_mkdir(config, aol, packageDir)

    if aol.linker.startswith('ming'):
        packageDir2 = mingwToNativePath(config, aol, packageDir)
    else:
        packageDir2 = packageDir

    packageInfoFilename2 = packageDir2 + '/metadata.json'

    if verbose(config):
        print('packageInfoFilename2 = ' + packageInfoFilename2)

    contentsFile2 = packageDir2 + '/contents.txt'

    if verbose(config):
        print('contentsFile2 = ' + contentsFile2)

    if os.path.exists(contentsFile2):
        print('contentsFile2 = FOUND')
        with open(contentsFile2) as f:
            content = f.readlines()

        content = [x.strip() for x in content]
        for item in content:
            print('-----' + item)

    else:
        print('contentsFile2 = NOT Found')




####################################################################################################
# Install package
####################################################################################################

def installPackage(config, aol, artifactId, mavenGroupId, mavenArtifactId, requiredVersion, localRepositoryPath):

    if debug(config):
        print('installPackage:')
        print('    artifactId = ' + artifactId)
        print('    mavenGroupId = ' + mavenGroupId)
        print('    mavenArtifactId = ' + mavenArtifactId)
        print('    requiredVersion = ' + requiredVersion)
        print('    localRepositoryPath = ' + localRepositoryPath)

    packageName = getPackageName(artifactId)


    fileName = mavenArtifactId + '-' + requiredVersion + '.' + PACKAGING

    home = myExpandUserHome(config, aol)
    path = mavenGroupId.replace('.', '/') + '/' + mavenArtifactId + '/' + requiredVersion
    localpath = home + '/.m2/repository/' + path + '/' + fileName

    if verbose(config):
        print('Installing package: ' + packageName)
    if debug(config):
        print('    localpath = ' + localpath)

    superuser_unzip(config, aol, localpath, INSTALL_DIR)

    localMetadata = readLocalRepositoryPackageMetadata(config, localRepositoryPath)
    lastChecked = localMetadata['lastChecked']

    key = 'originalFilename'
    if key in localMetadata:
        originalFilename = localMetadata[key]
    else:
        print('Error: The localMetadata for ' + packageName + ' does not contain the key "' + key + '"')
        print('localRepositoryPath = ' + localRepositoryPath)
        print(json.dumps(localMetadata, sort_keys=True, indent=4))
        sys.exit(3)

    #------------------------------------------------------
    # Copy the 'originalFilename' to the installed metadata
    #------------------------------------------------------
    packageDir = INSTALL_DIR + 'packages/' + packageName

    if verbose(config):
        print('packageDir = ' + packageDir)

    mkdir(config, aol, packageDir)

    if aol.linker.startswith('ming'):
        packageDir2 = mingwToNativePath(config, aol, packageDir)
    else:
        packageDir2 = packageDir

    packageInfoFilename2 = packageDir2 + '/metadata.json'

    if verbose(config):
        print('packageInfoFilename2 = ' + packageInfoFilename2)

    if os.path.exists(packageInfoFilename2):
        with open(packageInfoFilename2) as file:
            installedMetadata = json.load(file)
    else:
        installedMetadata = {}

    installedMetadata[key] = originalFilename

    with open(packageInfoFilename2, 'w') as outfile:
        json.dump(installedMetadata, outfile, sort_keys=True, indent=4)

    if debug(config):
        print('Package install metadata')
        print(json.dumps(installedMetadata, sort_keys = True, indent = 4))

    #------------------------------------------------------
    # Save a list of the zipfile contents (so the package can be un-installed)
    #------------------------------------------------------
    if aol.linker.startswith('ming'):
        localpath2 = mingwToNativePath(config, aol, localpath)
    else:
        localpath2 = localpath

    with zipfile.ZipFile(localpath2, 'r') as z:
        list = z.namelist()

    contentsFile2 = packageDir2 + '/contents.txt'

    if verbose(config):
        print('contentsFile2 = ' + contentsFile2)

    with open(contentsFile2, 'w') as f:
        for item in list:
            f.write(item + '\n')


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
    rmdir(config, aol, BUILD_DIR, BUILDTEMP_DIR)


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
        reposArtifactId = reposArtifactId.replace('/', '.')

        mavenGroupId = groupId + '.' + reposArtifactId
        mavenArtifactId = artifactId + '-' + str(aol)

        if verbose(config):
            print('dependency:')
            print('    groupId    = ' + groupId)
            print('    artifactId = ' + artifactId)
            print('    version    = ' + requiredVersion)
        if debug(config):
            print('    mavenGroupId    = ' + mavenGroupId)
            print('    mavenArtifactId = ' + mavenArtifactId)
            print('    aol             = ' + str(aol))

        localRepositoryPath = expanduser('~') + '/.m2/repository/' + mavenGroupId.replace('.', '/') + '/' + mavenArtifactId + '/' + requiredVersion
        localRepositoryPath = os.path.normpath(localRepositoryPath)
        fileName = mavenArtifactId + '-' + requiredVersion
        isSnapshot = requiredVersion.endswith('SNAPSHOT')

        needToDownload, needToInstall, repository = checkVersionOfInstalledPackage(config, aol, artifactId, requiredVersion, mavenGroupId, mavenArtifactId, localRepositoryPath)

        if needToDownload:
            downloadArtifact(config, repository, localRepositoryPath, fileName, mavenGroupId, mavenArtifactId, requiredVersion, isSnapshot)

        if needToInstall:
            unInstallPackage(config, aol, artifactId, mavenGroupId, mavenArtifactId, requiredVersion, localRepositoryPath)
            installPackage(config, aol, artifactId, mavenGroupId, mavenArtifactId, requiredVersion, localRepositoryPath)


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

    mkdir(config, aol, BUILD_OUTPUT_MAIN_DIR)

    writeCompileTimeMetadata(config, aol)

    if aol.operatingSystem == 'windows':
        makefile = os.path.relpath(SRC_MAIN_MAKE_DIR, BUILD_OUTPUT_MAIN_DIR) + '\\' + str(aol) + '.makefile'
        source = os.path.relpath(SRC_MAIN_C_DIR, BUILD_OUTPUT_MAIN_DIR)
        dist = os.path.relpath(DIST_DIR, BUILD_OUTPUT_MAIN_DIR)

        env = os.environ
        env['BUILD_TYPE'] = 'static'
        env['SOURCE'] = source
        env['DIST'] = dist
        env['INSTALL'] = INSTALL_DIR

        if verbose(config):
            print('cd ' + BUILD_OUTPUT_MAIN_DIR)
            print('set BUILD_TYPE=' + 'static')
            print('set SOURCE=' + source)
            print('set DIST=' + dist)
            print('set INSTALL=' + INSTALL_DIR)
            print('make -f ' + makefile + 'clean all')

        p = subprocess.Popen(['make', '-f', makefile, 'clean', 'all'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=BUILD_OUTPUT_MAIN_DIR)
        checkProcessCompletesOk(config, p, 'Error: Compile failed')


    else:     # Linux or MinGW or CygWin
        p = subprocess.Popen(['make', 'clean', 'all'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=BUILD_SOURCE_MAIN_DIR)
        checkProcessCompletesOk(config, p, 'Error: Compile failed')


####################################################################################################
# Make check
####################################################################################################

def defaultCheck(config, aol):
    print('defaultCheck')

    mkdir(config, aol, BUILD_OUTPUT_MAIN_DIR)

    if aol.operatingSystem == 'windows':
        makefile = os.path.relpath(SRC_MAIN_MAKE_DIR, BUILD_OUTPUT_MAIN_DIR) + '\\' + str(aol) + '.makefile'
        source = os.path.relpath(SRC_MAIN_C_DIR, BUILD_OUTPUT_MAIN_DIR)
        dist = os.path.relpath(DIST_DIR, BUILD_OUTPUT_MAIN_DIR)

        env = os.environ
        env['BUILD_TYPE'] = 'static'
        env['SOURCE'] = source
        env['DIST'] = dist
        env['INSTALL'] = INSTALL_DIR

        if verbose(config):
            print('cd ' + BUILD_OUTPUT_MAIN_DIR)
            print('set BUILD_TYPE=' + 'static')
            print('set SOURCE=' + source)
            print('set DIST=' + dist)
            print('set INSTALL=' + INSTALL_DIR)
            print('make -f ' + makefile + ' check')

        p = subprocess.Popen(['make', '-f', makefile, 'check'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=BUILD_OUTPUT_MAIN_DIR)
        checkProcessCompletesOk(config, p, 'Error: Check failed')


    else:     # Linux or MinGW or CygWin
        p = subprocess.Popen(['make', 'check'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=BUILD_SOURCE_MAIN_DIR)
        checkProcessCompletesOk(config, p, 'Error: Check failed')


####################################################################################################
# defaultDistribution
####################################################################################################

def defaultDistribution(config, aol):
    print('defaultDistribution')
    pass



####################################################################################################
# defaultArchive
####################################################################################################

def defaultArchive(config, aol):
    print('defaultArchive')

    artifactId = config["artifactId"]
    localfile = BUILD_ARTIFACT_DIR + artifactId + '-' + str(aol)
    shutil.make_archive(localfile, PACKAGING, DIST_DIR)


####################################################################################################
# Test Compile
####################################################################################################

def defaultTestCompile(config, aol):

    if debug(config):
        print('defaultTestCompile:')

    if not os.path.exists(SRC_TEST_DIR):
        if (verbose(config)):
            print('There is no Test Source directory')
        return

    mkdir(config, aol, BUILD_OUTPUT_TEST_DIR)

    workingDir = BUILD_OUTPUT_TEST_DIR
    makefile = os.path.relpath(SRC_TEST_MAKE_DIR, workingDir) + '\\' + str(aol) + '.makefile'
    source = os.path.relpath(SRC_TEST_C_DIR, workingDir)
    dist = os.path.relpath(DIST_DIR, workingDir)

    makefile = makefile.replace('\\', '/')
    source = source.replace('\\', '/')
    dist = dist.replace('\\', '/')

    env = os.environ
    env['BUILD_TYPE'] = 'static'
    env['SOURCE'] = source
    env['DIST'] = dist
    env['INSTALL'] = INSTALL_DIR

    args = ['make', '-f', makefile, 'clean', 'all']

    if (verbose(config)):
        print('Args = ' + str(args))
        print('cwd = ' + workingDir)

    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=workingDir)
    stdout, stderr = p.communicate()
    returncode = p.wait()

    if (returncode != 0):
        print('Error: Test Compile failed')

    if (returncode != 0) or (verbose(config)):
        print('Working directory = ' + workingDir)
        print('---------[ stdout ]-----------------------------------------------------------------')
        print(stdout.decode('utf-8'))
        print('---------[ stderr ]-----------------------------------------------------------------')
        print(stderr.decode('utf-8'))
        print('---------[ returncode = ' + str(returncode) + ']--------------------------------------------------------')

    if (returncode != 0):
        sys.exit(1)


####################################################################################################
# Test
#
# child - The child dir under 'output/test' where we will recursively look for test executables
#     - on windows                          - '**/*.exe'
#     - where libtool is used (e.g. cygwin) - '.libs/'
#     - where gcc is used (e.g. linux)      - ''
####################################################################################################

def is_exe(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def defaultTest(config, aol, child=''):
    print('defaultTest')

    if not os.path.exists(BUILD_OUTPUT_TEST_DIR):
        if (verbose(config)):
            print('There is no Test Output directory')
        return

    testExecutables = []
    if aol.operatingSystem == 'windows':

        if (child == ''):
            pattern = BUILD_OUTPUT_TEST_DIR + '**/*.exe'
        else:
            pattern = BUILD_OUTPUT_TEST_DIR + child + '**/*.exe'

        if (debug(config)):
            print('pattern = ' + pattern)

        for filename in glob.iglob(pattern, recursive=True):
            if is_exe(filename):
                if (debug(config)):
                    print("Adding '" + filename + "' to list of test programs")
                testExecutables.append(filename)
            else:
                if (debug(config)):
                    print("'" + filename + "' is not a test program")

        source = BUILD_OUTPUT_MAIN_DIR + '**/*.dll'
        for file in glob.iglob(source, recursive=True):
            fileName = os.path.basename(file)
            destination = BUILD_OUTPUT_TEST_DIR + '/' + fileName
            shutil.copy2(file, destination)

    else:
        executable = stat.S_IEXEC

        for root, dirnames, filenames in os.walk(BUILD_OUTPUT_TEST_DIR + child):
            for filename in fnmatch.filter(filenames, '*'):
                pathname = os.path.join(root, filename)
                if os.path.isfile(pathname):
                    st = os.stat(pathname)
                    mode = st.st_mode
                    if mode & executable:
                        testExecutables.append(pathname.replace('\\', '/'))

    if len(testExecutables) == 0:
        print('Error: No tests were found under: ' + BUILD_OUTPUT_TEST_DIR)
        sys.exit(1)

    if (verbose(config)):
        print('Running ' + str(len(testExecutables)) + ' Tests')

    for program in testExecutables:

        source = os.path.relpath(SRC_TEST_C_DIR, BUILD_OUTPUT_TEST_DIR)
        dist = os.path.relpath(DIST_DIR, BUILD_OUTPUT_TEST_DIR)
        program_relative = os.path.relpath(program, BUILD_OUTPUT_TEST_DIR)

        if (verbose(config)):
            print('    Running = ' + program)
            print('    Program = ' + program_relative)
            print('    Working Directory = ' + BUILD_OUTPUT_TEST_DIR)

        if aol.operatingSystem == 'windows':
            args = ["cmd", "/c", program_relative]
        else:
            args = [program_relative]

        if verbose(config):
            print('Args = ' + str(args))

        env = os.environ
        env['SOURCE'] = source
        env['DIST'] = dist
        env['INSTALL'] = INSTALL_DIR


        mkdir(config, aol, BUILD_OUTPUT_TEST_DIR)

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
    reposArtifactId = reposArtifactId.replace('/', '.')

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

def main(clean=None, generate=None, configure=None, compile=None, check=None, distribution=None, archive=None, testCompile=None, test=None, deploy=None):

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
        goals = ['clean', 'generate', 'configure', 'compile', 'check', 'distribution', 'archive', 'testCompile', 'test', 'deploy']
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
    # Find the Architecture-OperatingSystem-Linker (AOL)
    ####################################################################################################
    aol = AOL()

    ####################################################################################################
    # Read Configuration files
    ####################################################################################################

    with open(args.file) as buildfile:
        config.update(json.load(buildfile))

    servers = getServersConfigurationFromSettingsFile(config, aol)
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
    global INSTALL_DIR

    if aol.operatingSystem == 'windows':
        INSTALL_DIR = INSTALL_DIR_WINDOWS
    else:
        INSTALL_DIR = INSTALL_DIR_LINUX

    mkdir(config, aol, INSTALL_DIR)


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

    if 'check' in goals:
        print('goal = check')
        if check == None:
            defaultCheck(config, aol)
        else:
            check(config, aol)

    if 'distribution' in goals:
        print('goal = distribution')
        if distribution == None:
            defaultDistribution(config, aol)
        else:
            distribution(config, aol)

    if 'archive' in goals:
        print('goal = archive')
        if archive == None:
            defaultArchive(config, aol)
        else:
            archive(config, aol)

    if 'testCompile' in goals:
        print('goal = testCompile')
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





