import os
import re
import time
import json
import logging
import requests

from kubernetes import client, config 

#class which define the image object, include the name and the imageid
class Image():
    def __init__(self, Imagename, ImageId):
        self.Imagename = Imagename
        self.ImageId = ImageId

#############################################################################
# function name: get_images_name
#       logger: log file handle 
#       handler: handle of the logger file
#       console: consule output handle
##############################################################################
def k8s_logging_init(logger, handler, console):    
    logger.setLevel(level = logging.INFO)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    console.setLevel(logging.INFO)

    logger.addHandler(handler)
    logger.addHandler(console)

    logger.info("Start print log Info level testing......")
    logger.debug("Start print Debug Info level testing......")
    logger.warning("Start print log warning level testing......")
    logger.critical("Start print log critical Info testing......")
    logger.info("Test Finish")
    
    return

#############################################################################
# function name: get_images_name
#       logger: log file handle 
#       outfile: output json file for all the images 
#
# Connect to API server, get all the namesapce 
# get the pods under each namesapce 
# then get the images used by pods, record the image name and the imageId.  
# Output to a json file. The struct like this
#   [{'namespace',
#   'status',
#   'Images'[
#       'Continer_IP',
#       'Pod_name',
#       'Image',
#       'ImageId' ]},{...},{...}....] 
#############################################################################
def get_images_name(logger, outfile):
    #image data
    img_data = [{}]
    img_data[0]['Namespace'] = ''
    img_data[0]['Status'] = ''
    img_data[0]['Images'] = []

    #get OS env and token 
    try:
        apisvr_add  = os.environ['KUBERNETES_SERVICE_HOST']
    except:
        apisvr_add = None

    try:
        apisvr_port = os.environ['KUBERNETES_SERVICE_PORT']
    except:
        apisvr_port = None

    if apisvr_port == None or apisvr_add == None :
        logger.critical("critical: Cannot get api server address or api server port, will use the defaul to have a try. ")
        os.environ.setdefault('KUBERNETES_SERVICE_PORT', '443')
        os.environ.setdefault('KUBERNETES_SERVICE_HOST', '10.0.0.1')
        apisvr_add  = os.environ['KUBERNETES_SERVICE_HOST']
        apisvr_port = os.environ['KUBERNETES_SERVICE_PORT']

    #get token // for debug
    if True == os.path.isfile("/var/run/secrets/kubernetes.io/serviceaccount/token"):
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as fil_obj:
            token = fil_obj.read()
    else:
        #for debug
        print("error")    
        logger.critical("Token file read error")

    if True == os.path.isfile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"):
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as fil_obj:
            cert = fil_obj.read()
    else:
        #for debug
        print("error")    
        logger.critical("Cert file read error")


    #create a https connection to API server
    api_rul = 'https://{}:{}'.format(apisvr_add, apisvr_port)

    configuration = client.Configuration()

    config.load_incluster_config()
    config.host = api_rul

    # must run those three files at first: cluster_view.yaml   k8squary.yaml role_service_account.yaml
    v1 = client.CoreV1Api()
    ret = v1.list_namespace()
    pos = 0
    #save the name, pod and image information to a json file
    for i in ret.items:
        if (i.metadata.name == 'kube-system' or i.metadata.name == 'kube-public' or i.metadata.name == 'kube-node-lease'):
            continue
        strNameSpace = i.metadata.name
        stStatus  = i.status.phase
        img_data[pos]['Namespace']= strNameSpace
        img_data[pos]['Status']= stStatus
        print("NameSpace: %s, Status.phase: %s " , strNameSpace, stStatus)
        #get pods & image by namespace
        np_pods = v1.list_namespaced_pod(namespace = strNameSpace)
        for cntns in np_pods.items:
            for status in cntns.status.container_statuses:
                Continer_IP = cntns.status.pod_ip
                Pod_name = cntns.metadata.name
                Image = status.image 
                ImageId = status.image_id
                img_data[pos]['Images'].append({
                   'Continer_IP' : Continer_IP,
                   'Pod_name' : Pod_name,
                   'Image' : Image,
                   'ImageId': ImageId
                })
                continue
            continue

        pos += 1
        continue
    #save to json file
    json.dump(img_data, outfile)
    return 

#############################################################################
# function name: check_whether_new_images_appeared
#       outfile:        Json format file with all images info in it
#       images_list:    Old images list, if we find a new image, append at end this list
#       newimagelist:   Newly appeared images list
#
#
#############################################################################
def check_whether_new_images_appeared(images_dict, images_list, newimagelist):
    for namespc in images_dict:
        bFind = False
        images = namespc['Images']
        for image_nmspc in images:
            bFind = False
            imageId = image_nmspc['ImageId']
            imagename = image_nmspc['Image']
            for image in images_list:
                if (image.ImageId == imageId):
                    bFind = True
                    break 
                else: 
                    continue #next image
            #find a new image, add to image_list and newimagelist
            if bFind == False:
                images_list.append(Image(
                    imagename,
                    imageId))
                newimagelist.append(Image(
                    imagename,
                    imageId ))
            continue # next image in this namespace 
        continue #next name space
    return

#############################################################################
# function name: call_trivy_scan_new_image
#       newimagelist:   Newly appeared images list
#       scanresultfilelist:  filenames list, xxxx/yyyy:vvvv will be the xxxx_yyyy-vvvv.json in the list. 
#
#
#############################################################################
def call_trivy_scan_new_image(newimagelist, scanresultfilelist):
    scanresultfilelist.clear()

    for image in newimagelist:
        Imagename = image.Imagename
        #imageId = image.ImageId
        Imagename = Imagename.replace('/','_')
        Imagename = Imagename.replace(':','-')
        cmd = 'trivy -f json -o {}.json --exit-code 0 --severity HIGH --quiet --auto-refresh {}'.format(Imagename,image.Imagename)
        try:
            print(cmd)
            os.system(cmd)
        except:
            logger.critical("Call trivy failed")

        scanresultfilelist.append('{}.json'.format(Imagename))
        continue
    return 

#############################################################################
# function name: analysis_scanresult
#       scanresultfilelist:  filenames list, xxxx/yyyy:vvvv will be the xxxx_yyyy-vvvv.json in the list. 
#       newimagelist:   Newly appeared images list, for transfer the name and the ID of the images
#
#
#############################################################################
def analysis_scanresult(scanresultfilelist, newimagelist):
    res_data = {}
    for filepath in scanresultfilelist:
        #assemble the image name 
        with open(filepath,'r')as jsonfile:
             data = json.load(jsonfile)
        stype =  data[0]['Type']
              
        res_data['ImageName'] = data[0]['Target']
        res_data['Type'] = data[0]['Type']
        res_data['Vulnerabilities'] = []

        Vulnerabilities = data[0]['Vulnerabilities']
        for vul in Vulnerabilities:
            vulId =vul['VulnerabilityID']
            pkgname = vul['PkgName']
            Severity = vul['Severity']
            
            V3Score_nvd = 0
            V3Score_redhat = 0
            if ('CVSS' in vul):
                CVSS  = vul['CVSS']
                if ('nvd' in CVSS ):
                    if ('V3Score' in vul['CVSS']['nvd']):
                        V3Score_nvd = vul['CVSS']['nvd']['V3Score']
                    else:
                        V3Score_nvd = vul['CVSS']['nvd']['V2Score']
                if ('redhat' in CVSS ):
                    if('V3Score' in vul['CVSS']['redhat']):
                        V3Score_redhat = vul['CVSS']['redhat']['V3Score']
                    else:
                        V3Score_redhat = vul['CVSS']['redhat']['V2Score']
                        
            V3Score = max(V3Score_redhat, V3Score_nvd)   
            strscore = str(V3Score)
            if  Severity != 'MEDIUM' and Severity != 'LOW':
                res_data['Vulnerabilities'].append({
                    'VulnerabilityID': vulId,
                    'PkgName':  pkgname,
                    'Severity': Severity,
                    'V3Score': strscore
                })
            continue
        #print("%s" % data['Type'])
        resultfilelst = filepath.rsplit(".", 1)
        resultfile = resultfilelst[0]+"-vulresult"+".json"
        print(resultfile)
        with open(resultfile,'w') as outfile:
            json.dump(res_data, outfile)
        outfile.close()
        res_data.clear()
        continue #next image scan result file. 
    return


#########################################################
# Real functions starts from here
#     x     x
#      x  x
#      x  x
#    x      x
##########################################################

#init logging model
logger = logging.getLogger(__name__)
handler = logging.FileHandler("K8squary_log.txt")
console = logging.StreamHandler()
k8s_logging_init(logger, handler, console)

loop_around = 0 
flag = True
logger.info("Initial finish, application started")
images_list = [] #A list that includs all used images 
newimagelist = [] #A list for storing newly appeared images, those images will be scaned 

while flag:
    loop_around += 1
    #Open a new file for storing the images
    with open('images.json','r+') as outfile:
        get_images_name(logger,outfile) 
        #outfile.flush()
        images_dict = json.load(outfile)
   
    #Analysis the iamges list to get the newly appeared 
    check_whether_new_images_appeared(images_dict,images_list,newimagelist)
    outfile.close()

    scanresultfilelist = []
    # if the image list changed, call trivy to scan it. and output the result to another json file.
    if newimagelist.count != 0:
        call_trivy_scan_new_image(newimagelist,scanresultfilelist)
                
        #Analysis the json file, output the abstract of the vulenabilioty to the 
        analysis_scanresult(scanresultfilelist,newimagelist)
        scanresultfilelist.clear()
        newimagelist.clear()

    time.sleep(3600) #sleep for one hour
    #get result and scan the iamge, create the 
exit()