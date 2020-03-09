#!/usr/bin/env python
PROGRAM_NAME = "cg-site-health-check.py"
PROGRAM_DESCRIPTION = """
CloudGenix script
---------------------------------------

TODO: Jitter/Latency/Loss measurements per link
TODO: Determin endpoint for service links (which zscaler node/prisma cloud)
TODO: Only Major and Critical alarms/alerts

"""
from cloudgenix import API, jd
import os
import sys
import argparse
from fuzzywuzzy import fuzz
from datetime import datetime,timedelta   
import numpy as np
import requests 
import json
from lxml import html
import cloudgenix_idname

print_console = True
print_pdf = False
print_colors = True
print_html = False
html_buffer = "<!DOCTYPE html><html>"
last_style = ""

dns_trt_thresholds = {
    'fail': 120,
    'warn': 50
}

CLIARGS = {}
cgx_session = API(update_check=False)              #Instantiate a new CG API Session for AUTH
diff_hours = 24              #Hours to look back at

pan_service_dict = {
                "Prisma Access": 'q8kbg3n63tmp',
                "Prisma Cloud Management": "61lhr4ly5h9b",
                "Prisma Cloud": '1nvndw0xz3nd',
                "Prisma SaaS": 'f0q7vkhppsgw',
}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def convert_style_html(text):
    text = text.replace(bcolors.HEADER, '</div><div style="font-weight: bold; display: inline-block; ">')
    text = text.replace(bcolors.OKBLUE, '</div><div style="text-decoration-color: blue; display: inline-block;">')
    text = text.replace(bcolors.OKGREEN, '</div><div style="text-decoration-color: GREEN; display: inline-block;">')
    text = text.replace(bcolors.WARNING, '</div><div style="text-decoration-color: yellow; display: inline-block;;">')
    text = text.replace(bcolors.FAIL, '</div><div style="text-decoration-color: RED; display: inline-block;">')
    

    text = text.replace(bcolors.BOLD, '</div><div style="font-weight: bold; display: inline-block;">')
    text = text.replace(bcolors.UNDERLINE, '</div><div style="text-decoration: underline; display: inline-block;">')

    text = text.replace(bcolors.ENDC, '</div>')

    if not(str(text).startswith("<div>")):
        text = '<div style="display: inline-block;">' + text
    if not(str(text).endswith("</div>")):
        text = text + "</div>"
    return(text)
    

def pBold(str_to_print):
    return(bcolors.BOLD + str_to_print + bcolors.ENDC)
def pFail(str_to_print):
    return(bcolors.FAIL + str_to_print + bcolors.ENDC)
def pPass(str_to_print):
    return(bcolors.OKGREEN + str_to_print + bcolors.ENDC)
def pWarn(str_to_print):
    return(bcolors.WARNING + str_to_print + bcolors.ENDC)
def pExceptional(str_to_print):
    return(bcolors.OKBLUE + str_to_print + bcolors.ENDC)
def pUnderline(str_to_print):
    return(bcolors.UNDERLINE + str_to_print + bcolors.ENDC)
def dns_trt_classifier(dns_trt_time):
    if( dns_trt_time > dns_trt_thresholds['fail']):
        return pFail(str(dns_trt_time))
    elif (dns_trt_time > dns_trt_thresholds['warn']):
        return pWarn(str(dns_trt_time))
    else:
        return pPass(str(dns_trt_time))
def metric_classifier(value, expected, error_percentage_as_decimal, warn_percentage_as_decimal=0.05):
    if (value < (expected - ( expected * error_percentage_as_decimal ) )):
        return pFail(str(value))
    
    if (value >= expected + (expected * error_percentage_as_decimal * 2) ):
        return pExceptional(str(value))

    if (value >= expected - (expected * warn_percentage_as_decimal) ):
        return pPass(str(value))
    
    return pWarn(str(value))
    

class dbbox:
    dl = u'\u255a'
    ul = u'\u2554'
    dc = u'\u2569'
    uc = u'\u2566'
    lc = u'\u2560'
    u = u'\u2550'
    c = u'\u256c'
    l = u'\u2551'

P1 = "P1"
H1 = "H1"
H2 = "H2"
B1 = "B1"
B2 = "B2"
END_SECTION = "END_SECTION"


def vprint(text, style="B1"):
    global last_style
    global html_buffer
    if print_colors == False:
        for color in filter(lambda a: not a.startswith('__'), dir(bcolors())):
            text = text.replace(getattr(bcolors,color),"")
    if print_console == True:
        if (text == "END_SECTION"):
            print(dbbox.dl + (dbbox.u*20))
            print(" ")
        elif (style == "P1"):
            print(dbbox.ul + (dbbox.u*20))
            print(dbbox.l + pBold(text))
            print(dbbox.dl + (dbbox.u*20))
        elif (style == "H1"):
            print(dbbox.ul + (dbbox.u*20))
            print(dbbox.l + pBold(text))
            print(dbbox.lc + (dbbox.u*20))
        elif (style == "H2"):
            print(dbbox.lc + (dbbox.u*20))
            print(dbbox.l + pBold(text))
            print(dbbox.lc + (dbbox.u*20))
        elif (style == "B1"):
            print(dbbox.l + text)
        elif (style == "B2"):
            print(dbbox.l + " " + text)

    if (print_pdf == True):
        pass
    if (print_html == True):
        if (text == "END_SECTION"):
            html_buffer += "</div>"
        else:
            #html_buffer += '<div style="display:inline">'
            html_buffer += '<div style="display: inline-block">'
            if style == "B1":
                style == "BODY"
            if style == "B2":
                style == "UL"
            if (last_style != style and last_style != ""): ###NEW STYLE
                html_buffer += "</" + str(last_style) + ">"
                html_buffer += "<" + str(style) + ">"
                html_buffer += "<" + str(style) + ">"
                last_style = style
            html_buffer += str(convert_style_html(text))
            html_buffer += '</div></br>'




def getpanstatus(webcontent, str_service):
    services_list = webcontent.xpath('//*[@data-component-id="' + str_service + '"]/span')
    if (len(services_list) == 4):
        service_status = (services_list[2].text).lstrip().rstrip()
    else:
        service_status = (services_list[1].text).lstrip().rstrip()
    return service_status

def parse_arguments():
    parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=PROGRAM_DESCRIPTION
            )
    parser.add_argument('--token', '-t', metavar='"MYTOKEN"', type=str, 
                    help='specify an authtoken to use for CloudGenix authentication')
    parser.add_argument('--authtokenfile', '-f', metavar='"MYTOKENFILE.TXT"', type=str, 
                    help='a file containing the authtoken')
    parser.add_argument('--site-name', '-s', metavar='SiteName', type=str, 
                    help='The site to run the site health check for', required=True)
    args = parser.parse_args()
    CLIARGS.update(vars(args)) ##ASSIGN ARGUMENTS to our DICT
def authenticate():
    vprint("Authenticating",H1)
    
    user_email = None
    user_password = None
    
    ##First attempt to use an AuthTOKEN if defined
    if CLIARGS['token']:                    #Check if AuthToken is in the CLI ARG
        CLOUDGENIX_AUTH_TOKEN = CLIARGS['token']
        vprint("Authenticating using Auth-Token in from CLI ARGS", B1)
    elif CLIARGS['authtokenfile']:          #Next: Check if an AuthToken file is used
        tokenfile = open(CLIARGS['authtokenfile'])
        CLOUDGENIX_AUTH_TOKEN = tokenfile.read().strip()
        vprint("Authenticating using Auth-token from file: " + pUnderline(CLIARGS['authtokenfile']), B1)
    elif "X_AUTH_TOKEN" in os.environ:              #Next: Check if an AuthToken is defined in the OS as X_AUTH_TOKEN
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
        vprint("Authenticating using environment variable X_AUTH_TOKEN", B1)
    elif "AUTH_TOKEN" in os.environ:                #Next: Check if an AuthToken is defined in the OS as AUTH_TOKEN
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
        vprint("Authenticating using environment variable AUTH_TOKEN", B1)
    else:                                           #Next: If we are not using an AUTH TOKEN, set it to NULL        
        CLOUDGENIX_AUTH_TOKEN = None
        vprint("Authenticating using interactive login", B1)
    ##ATTEMPT AUTHENTICATION
    if CLOUDGENIX_AUTH_TOKEN:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            vprint(pFail("ERROR") + ": AUTH_TOKEN login failure, please check token.", B1)
            sys.exit()
    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None            
    vprint(pPass("SUCCESS") + ": Authentication Complete", B1)
    vprint(END_SECTION)

def go():
    global html_buffer
    idname =  cloudgenix_idname.CloudGenixIDName(cgx_session)
    vpnpaths_id_to_name = idname.generate_anynets_map()
    

    #keyname_dict = cloudgenix_idname.generate_id_name_map(cgx_session, reverse=True)

    ####CODE GOES BELOW HERE#########
    resp = cgx_session.get.tenants()
    if resp.cgx_status:
        tenant_name = resp.cgx_content.get("name", None)
        vprint("TENANT NAME: " + pUnderline(tenant_name), "H1")
        
    else:
        logout()
        vprint(pFail("ERROR") + ": API Call failure when enumerating TENANT Name! Exiting!", P1)
        print(resp.cgx_status)
        sys.exit((vars(resp)))

    site_count = 0
    search_site = CLIARGS['site_name']
    search_ratio = 0
    site_name = ""
    site_id = ""


    ###FIND the site in question
    resp = cgx_session.get.sites()
    if resp.cgx_status:
        site_list = resp.cgx_content.get("items", None)    #EVENT_LIST contains an list of all returned events
        for site in site_list:                            #Loop through each EVENT in the EVENT_LIST
            check_ratio = fuzz.ratio(search_site.lower(),site['name'].lower())
            if (check_ratio > search_ratio ):
                site_id = site['id']
                site_name = site['name']
                search_ratio = check_ratio
                
    else:
        logout()
        vprint(pFail("ERROR") + "API Call failure when enumerating SITES in tenant! Exiting!", P1)
        sys.exit((jd(resp)))

    vprint("Health Check for SITE: '" + pUnderline(pBold(site_name)) + "' SITE ID: " + pBold(site_id), B1)
    vprint(END_SECTION)

    ###Check if elements are online
    site_elements = []
    element_count = 0
    resp = cgx_session.get.elements()
    if resp.cgx_status:
        
        vprint("ION Status for site", H1)
        
        element_list = resp.cgx_content.get("items", None)    #EVENT_LIST contains an list of all returned events
        
        if (len(element_list) >= 0):
            for element in element_list:                            #Loop through each EVENT in the EVENT_LIST
                if (element['site_id'] == site_id):
                    element_count += 1
                    site_elements.append(element['id'])
                    if (element_count > 1):
                        print(dbbox.l)
                    vprint("ION found NAME: " + pBold(str(element['name'])) + " ION ID: " + pBold(str(element['id'])), B1)
                    if (element['connected'] == True):
                        vprint("ION Status: " + pPass("CONNECTED"), B2)
                    else:
                        vprint("ION Status: " + pFail("OFFLINE (!!!)"), B2)
        if (element_count == 0):
            vprint("ION Status: " + pBold("No IONS for site found"), B1)
        vprint(END_SECTION)
    
    ################### ALARMS ###################
    ### Get last 5 ALARMS for last diff_hours hours
    
    dt_now = str(datetime.now().isoformat())
    dt_start = str((datetime.today() - timedelta(hours=diff_hours)).isoformat())
    dt_yesterday = str((datetime.today() - timedelta(hours=48)).isoformat())
    
    event_filter = '{"limit":{"count":5,"sort_on":"time","sort_order":"descending"},"view":{"summary":false},"severity":[],"query":{"site":["' + site_id + '"],"category":[],"code":[],"correlation_id":[],"type":["alarm"]}, "start_time": "' + dt_start + '", "end_time": "'+ dt_now + '"}'
    resp = cgx_session.post.events_query(event_filter)
    if resp.cgx_status:
        vprint("Last 5 Alarms for site within the past "+ str(diff_hours) +" hours", H1)
        
        alarms_list = resp.cgx_content.get("items", None)
        if(len(alarms_list) == 0 ):
            vprint("No Alarms found in the past " + str(diff_hours) + " hours",B1)
        else:
            for alarm in alarms_list:
                vprint("ALARM: " + str(alarm['code']),B1)
                vprint("Acknowledged: " + str(alarm['cleared']),B2)
                if (alarm['severity'] == "minor"):
                    vprint("Severity    : " + pWarn(str(alarm['severity'])),B2)
                elif (alarm['severity'] == "major"):
                    vprint("Severity    : " + pFail(str(alarm['severity'])),B2)
                else:
                    vprint("Severity    : " + str(alarm['severity']),B2)
                vprint("Timestamp   : " + str(alarm['time']),B2)
    else:
        vprint(pFail("ERROR in SCRIPT. Could not get ALARMS"),B1)

    ### Get SUMMARY ALARMS  for last diff_hours hours
    alarm_summary_dict = {}
    event_filter = '{"limit":{"count":1000,"sort_on":"time","sort_order":"descending"},"view":{"summary":false},"severity":[],"query":{"site":["' + site_id + '"],"category":[],"code":[],"correlation_id":[],"type":["alarm"]}, "start_time": "' + dt_start + '", "end_time": "'+ dt_now + '"}'
    resp = cgx_session.post.events_query(event_filter)
    if resp.cgx_status:
        vprint("Alarm Summaries for the past " + pUnderline( str(diff_hours)) + pBold(" hours"), H2)
        alarms_list = resp.cgx_content.get("items", None)
        if(len(alarms_list) > 0 ):
            for alarm in alarms_list:
               if(alarm['code'] in alarm_summary_dict.keys() ):
                   alarm_summary_dict[alarm['code']] += 1
               else:
                   alarm_summary_dict[alarm['code']] = 1
            for alarm_code in alarm_summary_dict.keys():
                vprint("CODE: " + str(alarm_code), B1 )
                vprint("TOTAL Count: " + pUnderline(str(alarm_summary_dict[alarm_code])), B2)
        else:
            vprint("No Alarm summaries", B1 )
    else:
        vprint(pFail("ERROR in SCRIPT. Could not get ALARMS"),B1)
    vprint(END_SECTION)

    ################### ALERTS ###################
    ### Get last 5 ALERTS for last diff_hours hours
    event_filter = '{"limit":{"count":5,"sort_on":"time","sort_order":"descending"},"view":{"summary":false},"severity":[],"query":{"site":["' + site_id + '"],"category":[],"code":[],"correlation_id":[],"type":["alert"]}, "start_time": "' + dt_start + '", "end_time": "'+ dt_now + '"}'
    resp = cgx_session.post.events_query(event_filter)
    if resp.cgx_status:
        vprint("Last 5 Alerts for site within the past "+ str(diff_hours) +" hours", H1)
        
        alerts_list = resp.cgx_content.get("items", None)
        if(len(alerts_list) == 0 ):
            vprint("No Alerts found", B1)
        else:
            for alert in alerts_list:
                vprint("ALERT CODE: " + pBold(str(alert['code'])), B1 )
                if ( 'reason' in alert['info'].keys()):
                    vprint("REASON    : " + str(alert['info']['reason']), B2)
                if ( 'process_name' in alert['info'].keys()):
                    vprint("PROCESS   : " + str(alert['info']['process_name']), B2)
                if ( 'detail' in alert['info'].keys()):
                    vprint("DETAIL    : " + str(alert['info']['detail']), B2)
                if (alert['severity'] == "minor"):
                    vprint("SEVERITY  : " + pWarn(str(alert['severity'])), B2)
                elif (alert['severity'] == "major"):
                    vprint("SEVERITY  : " + pFail(str(alert['severity'])), B2)
                else:
                    vprint("SEVERITY  : " + (str(alert['severity'])), B2)
                vprint("TIMESTAMP : " + str(alert['time']), B2)
    else:
        vprint("ERROR in SCRIPT. Could not get Alerts")

    ### Get ALERTS summary for last diff_hours hours
    alert_summary_dict = {}
    event_filter = '{"limit":{"count":1000,"sort_on":"time","sort_order":"descending"},"view":{"summary":false},"severity":[],"query":{"site":["' + site_id + '"],"category":[],"code":[],"correlation_id":[],"type":["alert"]}, "start_time": "' + dt_start + '", "end_time": "'+ dt_now + '"}'
    resp = cgx_session.post.events_query(event_filter)
    if resp.cgx_status:
        vprint("Alert Summaries for the past " + pUnderline( str(diff_hours)) + pBold(" hours"), H1)
        

        alerts_list = resp.cgx_content.get("items", None)
        if(len(alerts_list) > 0 ):
            for alert in alerts_list:
               if(alert['code'] in alert_summary_dict.keys() ):
                   alert_summary_dict[alert['code']] += 1
               else:
                   alert_summary_dict[alert['code']] = 1
            for alert_code in alert_summary_dict.keys():
                vprint("CODE: " + str(alert_code), B1 )
                vprint("TOTAL Count: " + pUnderline(str(alert_summary_dict[alert_code])), B2)
        else:
            vprint("No Alarm summaries",B1 )
    else:
        vprint(pFail("ERROR in SCRIPT. Could not get Alerts"), B1)
    vprint(END_SECTION)

    elements_id_to_name = idname.generate_elements_map()
    site_id_to_name = idname.generate_sites_map()
    wan_label_id_to_name = idname.generate_waninterfacelabels_map()
    wan_if_id_to_name = idname.generate_waninterfaces_map()
    
    wan_interfaces_resp = cgx_session.get.waninterfaces(site_id)
    wan_interfaces_list = wan_interfaces_resp.cgx_content.get("items")

    ### GET  LINKS status (VPN/PHYS)
    topology_filter = '{"type":"basenet","nodes":["' +  site_id + '"]}'
    resp = cgx_session.post.topology(topology_filter)
    if resp.cgx_status:
        topology_list = resp.cgx_content.get("links", None)
        vprint("VPN STATUS",H1) 
        vpn_count = 0 
        for links in topology_list:

            if ((links['type'] == 'vpn') and links['source_site_name'] == site_name):
                vpn_count += 1
                #print(dbbox.l + format(vpnpaths_id_to_name.get(links['path_id'], links['path_id'])))
                vprint("VPN " + str(vpn_count) + "-> SITE:" + site_name + " [ION:" + elements_id_to_name[links['source_node_id']] + "]" + " ---> "+  wan_if_id_to_name[links['source_wan_if_id']] + ":" + links['source_wan_network'] 
                       + " " +  (dbbox.u*3) + (dbbox.c) + (dbbox.u*3) + " " + links['target_wan_network'] + ":" + wan_if_id_to_name[links['target_wan_if_id']] + " <--- [" +  elements_id_to_name[links['target_node_id']] + "] " + links['target_site_name'], B1)
                if (links['status'] == "up"):
                    vprint("STATUS: " + pPass("UP"),B2)
                else:
                    vprint("STATUS: " + pFail("DOWN"), B2)
        if (vpn_count == 0):
            vprint("No SDWAN VPN links found at site",B1)
        vprint(END_SECTION)
        
         
        pcm_metrics_array_up = []  
        pcm_metrics_array_down = []  
        vprint("PHYSICAL LINK STATUS",P1)
        stub_count = 0
        for links in topology_list:
            if ((links['type'] == 'internet-stub')):
                stub_count += 1
                if ('target_circuit_name' in links.keys()):
                    vprint("Physical LINK: " + pBold(str(links['network'])) + ":" + pUnderline(str(links['target_circuit_name'])),H1 )
                else:
                    vprint("Physical LINK: " + pBold(str(links['network'])),H1 )                    
                if (links['status'] == "up"):
                    vprint("STATUS: " + pPass("UP"), B2)
                elif (links['status'] == "init"):
                    vprint("STATUS: " + pWarn("INIT"), B2)
                else:
                    vprint("STATUS: " + pFail("DOWN"),B2)
                
                ###PCM BANDWIDTH CAPACITY MEASUREMENTS
                pcm_request = '{"start_time":"'+ dt_start + 'Z","end_time":"' + dt_now + 'Z","interval":"5min","view":{"summary":false,"individual":"direction"},"filter":{"site":["' + site_id + '"],"path":["' + links['path_id'] + '"]},"metrics":[{"name":"PathCapacity","statistics":["average"],"unit":"Mbps"}]}'
                pcm_resp = cgx_session.post.metrics_monitor(pcm_request)
                pcm_metrics_array_up.clear()
                pcm_metrics_array_down.clear()
                measurements_up = 0
                measurements_down = 0
                z_count_down = 0
                z_count_up = 0
                if pcm_resp.cgx_status:
                    pcm_metric = pcm_resp.cgx_content.get("metrics", None)[0]['series']
                    if pcm_metric[0]['view']['direction'] == 'Ingress':
                        direction = "Download"
                    for series in pcm_metric:
                        if direction == "Download":                            
                            for datapoint in series['data'][0]['datapoints']:
                                if (datapoint['value'] == None):
                                    #pcm_metrics_array_down.append(0)
                                    z_count_down += 1
                                else:
                                    pcm_metrics_array_down.append(datapoint['value'])
                                    measurements_down += 1
                            direction = 'Upload'
                        else:
                            for datapoint in series['data'][0]['datapoints']:                                
                                if (datapoint['value'] == None):
                                    #pcm_metrics_array_up.append(0)
                                    z_count_up += 1
                                else:
                                    pcm_metrics_array_up.append(datapoint['value'])
                                    measurements_up += 1
                            direction = 'Download'

                    vprint("Configured Bandwidth/Throughput for the site")
                    
                    for wan_int in wan_interfaces_list:
                        if wan_int['id'] == links['path_id']:
                            upload = wan_int['link_bw_up']
                            download = wan_int['link_bw_down']
                            vprint("Maximum BW Download : " + str(wan_int['link_bw_down']),B2)
                            vprint("Maximum BW Upload   : " + str(wan_int['link_bw_up']),B2)
                    
                    error_percentage = 0.1
                    warn_percentage = 0.05
                    vprint("Measured Link Capacity (PCM) STATS for the last 24 hours", H2)
                    vprint("THRESHOLDS: "+ pFail("RED") + ">=" + (str(error_percentage*100)) + "% |  "+pWarn("YELLOW") + ">=" + (str(warn_percentage*100)) + "%  | "+ pPass("GREEN") + "=Within " + (str(warn_percentage*100)) + "% | " + pExceptional("BLUE") + "="+ (str(error_percentage*100*2)) + "% Above expected",B1)

                    vprint("Upload - Calculated from " + str(len(pcm_metrics_array_up)) + " Measurements in the past 24 Hours in mbits", H2)
                    if (len(pcm_metrics_array_up) == 0):
                        pcm_metrics_array_up.append(0)
                    if (len(pcm_metrics_array_down) == 0):
                        pcm_metrics_array_down.append(0)
                    
                    np_array = np.array(pcm_metrics_array_up)
                    
                    vprint("Zeros:" + str(z_count_up), B1)
                    vprint("25th percentile      : " + metric_classifier( round(np.percentile(np_array,25),3),upload,error_percentage,warn_percentage),B1)
                    vprint("50th Percentile(AVG) : " + metric_classifier( round(np.average(np_array),3),upload,error_percentage,warn_percentage),B1)
                    vprint("75th percentile      : " + metric_classifier( round(np.percentile(np_array,75),3),upload,error_percentage,warn_percentage),B1)
                    vprint("95th percentile      : " + metric_classifier( round(np.percentile(np_array,95),3),upload,error_percentage,warn_percentage),B1)
                    vprint("Max Value            : " + metric_classifier( round(np.amax(np_array),3),upload,error_percentage,warn_percentage),B1)
                    
                    vprint("Download - Calculated from " + str(len(pcm_metrics_array_down)) + " Measurements in the past 24 Hours", H2)
                    
                    np_array = np.array(pcm_metrics_array_down)
                    #vprint("Zeros:" + str(z_count_down), B1)
                    vprint("25th percentile      : " + metric_classifier( round(np.percentile(np_array,25),3),download,error_percentage,warn_percentage),B1)
                    vprint("50th Percentile(AVG) : " + metric_classifier( round(np.average(np_array),3),download,error_percentage,warn_percentage),B1)
                    vprint("75th percentile      : " + metric_classifier( round(np.percentile(np_array,75),3),download,error_percentage,warn_percentage),B1)
                    vprint("95th percentile      : " + metric_classifier( round(np.percentile(np_array,95),3),download,error_percentage,warn_percentage),B1)
                    vprint("Max Value            : " + metric_classifier( round(np.amax(np_array),3),download,error_percentage,warn_percentage),B1)
                vprint(END_SECTION)
                    

        if (stub_count == 0):
            vprint("No Physical links found at site", B1)
            vprint(END_SECTION)
        
        vprint("3RD PARTY LINK STATUS",H1)
        service_link_count = 0
        for links in topology_list:
            if ((links['type'] == 'servicelink')):
                service_link_count += 1
                vprint("3RD PARTY LINK: " + pBold(str(links['sep_name'])) + " VIA WAN " + pUnderline(str(links['wan_nw_name'])),B1 )
                if (links['status'] == "up"):
                    vprint("STATUS: " + pPass("UP"),B2)
                else:
                    vprint("STATUS: " + pFail("DOWN"),B2)
        if (service_link_count == 0):
            vprint("No 3rd party VPN tunnels found",B1)
        vprint(END_SECTION)
        
        
    #######DNS RESPONSE TIME:
    app_name_map = {}    
    app_name_map = idname.generate_appdefs_map(key_val="display_name", value_val="id")
    if ("dns" in app_name_map.keys()):
        dns_app_id = app_name_map['dns']   
        dns_request = '{"start_time":"' + dt_start + 'Z","end_time":"'+ dt_now + 'Z","interval":"5min","metrics":[{"name":"AppUDPTransactionResponseTime","statistics":["average"],"unit":"milliseconds"}],"view":{},"filter":{"site":["' + site_id + '"],"app":["' + dns_app_id + '"],"path_type":["DirectInternet","VPN","PrivateVPN","PrivateWAN","ServiceLink"]}}'
        dns_trt_array = []
        resp = cgx_session.post.metrics_monitor(dns_request)
        if resp.cgx_status:
            dns_metrics = resp.cgx_content.get("metrics", None)[0]['series'][0]
            for datapoint in dns_metrics['data'][0]['datapoints']:
                if (datapoint['value'] == None):
                    dns_trt_array.append(0)
                else:
                    dns_trt_array.append(datapoint['value'])
            
            vprint("DNS TRT STATS", H1)
            vprint("Stats for past 24 hours",H2)
            

            np_array = np.array(dns_trt_array)
            vprint("Min             : " + dns_trt_classifier( round(np.amin(np_array),2)),B1)
            vprint("average         : " + dns_trt_classifier( round(np.average(np_array),2)),B1)
            vprint("80th percentile : " + dns_trt_classifier( round(np.percentile(np_array,80),2)),B1)
            vprint("95th percentile : " + dns_trt_classifier( round(np.percentile(np_array,95),2)),B1)
            vprint("Max Value       : " + dns_trt_classifier( round(np.amax(np_array),2) ),B1)

            ### Get stats from 48 hours ago
            dns_request = '{"start_time":"' + dt_yesterday + 'Z","end_time":"'+ dt_start + 'Z","interval":"5min","metrics":[{"name":"AppUDPTransactionResponseTime","statistics":["average"],"unit":"milliseconds"}],"view":{},"filter":{"site":["' + site_id + '"],"app":["' + dns_app_id + '"],"path_type":["DirectInternet","VPN","PrivateVPN","PrivateWAN","ServiceLink"]}}'
            dns_trt_array.clear()
            resp = cgx_session.post.metrics_monitor(dns_request)
            dns_metrics = resp.cgx_content.get("metrics", None)[0]['series'][0]
            for datapoint in dns_metrics['data'][0]['datapoints']:
                if (datapoint['value'] == None):
                    dns_trt_array.append(0)
                else:
                    dns_trt_array.append(datapoint['value'])

            vprint("Stats from Yesterday",H2)
        
            np_array_yesterday = np.array(dns_trt_array)
            vprint("Min             : " + dns_trt_classifier( round(np.amin(np_array_yesterday),2)),B1)
            vprint("average         : " + dns_trt_classifier( round(np.average(np_array_yesterday),2)),B1)
            vprint("80th percentile : " + dns_trt_classifier( round(np.percentile(np_array_yesterday,80),2)),B1)
            vprint("95th percentile : " + dns_trt_classifier( round(np.percentile(np_array_yesterday,95),2)),B1)
            vprint("Max Value       : " + dns_trt_classifier( round(np.amax(np_array_yesterday),2)),B1)
    else:
        vprint(pFail("ERROR: DNS APPLICATION NOT FOUND"),B1)
    vprint(END_SECTION)

    ###Get PAN STATUS
    pan_core_services_url = 'https://status.paloaltonetworks.com/'
    pan_health_request = requests.get(url = pan_core_services_url)
    pan_tree_data = html.fromstring(pan_health_request.content)
    
    vprint("Palo Alto Prisma Cloud STATUS from: " + pUnderline(pan_core_services_url), H1)
    
    for service in pan_service_dict:
        service_status = getpanstatus(pan_tree_data, pan_service_dict[service] )
        if (service_status == "Operational"):
            vprint("SERVICE: " + service + "            STATUS: " + pPass(service_status), B1)
        else:
            vprint("SERVICE: " + service + "            STATUS: " + pFail(service_status), B1)
    vprint(END_SECTION)

    ###Get zScaler STATUS
    zs_core_services_url = 'https://trust.zscaler.com/api/cloud-status.json?_format=json&a=b'
    
    vprint("zScaler Cloud STATUS from: " + pUnderline(zs_core_services_url), H1)
    
    zs_post_data = '{"cloud":"trust.zscaler.net","dateOffset":0,"requestType":"core_cloud_services"}'
    zs_query_params = {'_format': 'json', 'a': 'b'}
    zs_headers =  {'Content-type': 'application/json'}

    zscaler_health_request = requests.post(url = zs_core_services_url, data = zs_post_data, params=zs_query_params, headers=zs_headers)

    zs_data = zscaler_health_request.json()

    zscaler_severity = {}
    for severity in zs_data['data']['severity']:
        zscaler_severity[severity['tid']] = severity['name']

    if ('data' in zs_data.keys()):
        if ('category' in zs_data['data'].keys()):
            for service in zs_data['data']['category'][0]['subCategory']:
                if ('category_status' in service.keys()):
                    vprint(service['name'] + " STATUS: " + pFail(zscaler_severity[service['category_status']['severityTid']] + "(" + service['category_status']['severityTid'] + ")"),B1)
                    vprint(pUnderline(service['category_status']['ri_date'] + ": ") + pBold( service['category_status']['short_description']).replace("&nbsp;"," "), B2)
                else:
                    vprint(service['name'] + " STATUS: " +  pPass("GOOD"),B1)
    vprint(END_SECTION)


    ### Check MSFT Cloud Serivces status:
    ms_core_services_url = 'https://portal.office.com/api/servicestatus/index'
    
    vprint("Microsoft Cloud STATUS from: " + pUnderline(ms_core_services_url), H1)
    
    ms_headers =  {'Content-type': 'application/json'}
    ms_health_request = requests.get(url = ms_core_services_url,  headers=ms_headers)
    ms_data = ms_health_request.json()

    if ('Services' in ms_data.keys()):
        for service in ms_data['Services']:
            if (service['IsUp']):
                vprint(service['Name'] + " STATUS: " + pPass("GOOD"), B1)
            else:
                vprint(service['Name'] + " STATUS: " + pFail("ISSUE DETECTED"), B1)
    vprint(END_SECTION)

    ### Check Google Cloud Serivces status:
    google_core_services_url = 'https://www.google.com/appsstatus/json/en'
    
    vprint("Google Cloud STATUS from: " + pUnderline(google_core_services_url), H1)
    
    google_headers =  {'Content-type': 'application/json'}
    google_health_request = requests.get(url = google_core_services_url,  headers=google_headers)
    google_data = json.loads(google_health_request.text.replace("dashboard.jsonp(","").replace("});","}"))

    google_service_list = {}
    for service in google_data['services']:
        google_service_list[service['id']] = service['name']

    google_issue_count = 0
    for messages in google_data['messages']:
        if (not(messages['resolved'])):
            google_issue_count += 1
            vprint(google_service_list[messages['service']] + " STATUS: " + pFail("ISSUE DETECTED"), B1)
    if (google_issue_count == 0):
        vprint(pPass("No unresolved google cloud issues detected"), B1)
    vprint(END_SECTION)

    if (print_html):
        html_buffer += "</html>"
        print(html_buffer)


def logout():
    print("Logging out")
    cgx_session.get.logout()
if __name__ == "__main__":
    parse_arguments()
    authenticate()
    go()
    logout()
