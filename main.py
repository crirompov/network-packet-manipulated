#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Author: Cristian Romero Povea
# Práctica 11 de la asignatura SSII en 4º curso del Grado Ingeniería Informática - Tecnologías Informáticas

import argparse
from prettytable import PrettyTable
from scapy.all import *

def main():
    target = []
    port = []
    #Load arguments:
    args = load_arguments()

    if get_arguments(args):
        target = split_params(args.target)
        if args.icmp:
            main_icmp_scan(target)
        if args.synstealth:
            if args.ports != None:
                port = split_params(args.ports)
            else:
                port = get_list_ports_default()
            main_syn_scan(target,port)
    else:
        exit()
    print"#############################################################"

def load_arguments():
    #Argumentos:
    parser = argparse.ArgumentParser()
    parser.add_argument("--synstealth", "-sS", help="Realiza un análisis mediante el envío de la flag SYN activo y analizando las respuestas del objetivo. Por defecto analiza los puertos típicos", action="store_true")
    parser.add_argument("--icmp", "-i", help="Para comprobar si el objetivo está activo mediante el envío de un ping", action="store_true")
    parser.add_argument("--ports", "-p", help="Podemos especificar un puerto o un rango de estos, separados por ',', para analizar. El rango de puertos tiene que ser especificado de la siguiente manrea '-p startPort-endPort'. Por defecto se analizan los 1000 primeros puertos")
    parser.add_argument("--target", "-T", help="Especificamos las direcciones IPs objetivo. Para separar una dirección IP de otra, se usará una coma ','. Podemos escanear una red especificando la red ex: 192.168.1.0/24")
    args = parser.parse_args()
    return args

def main_syn_scan(targets,ports):
    print "###########################################"
    print "#                SYN SCAN                 #"
    print "###########################################"
    print "*******************************************"
    print "###########################################"
    get_result_syn_scan_atom(targets,ports)
    print "###########################################"
    print "*******************************************"

def main_icmp_scan(targets):
    print "###########################################"
    print "#                ICMP SCAN                #"
    print "###########################################"
    print "*******************************************"
    print "###########################################"
    scan_host_ICMP(targets)
    print "###########################################"
    print "*******************************************"

def get_arguments(argsP):
    if (argsP.synstealth == True) or (argsP.icmp == True):
        return True
    else:
        print "[ERROR] Los parámetros introducidos no son correctos."
        return False

def get_result_table_syn_scan(server_response):
    table = PrettyTable()
    table.field_names = ["Port","State"]
    for a,b in server_response:
        aux_flags = "Open"
        if TCP in b:
            if b[TCP].flags != "SA":
                aux_flags = "Close"
            table.add_row([a.dport, aux_flags])
    print table

def syn_scan_for_host(target,port):
    print "{"
    p = IP(dst=target)/TCP(dport=port, flags="S")
    ans, nans= sr(p, timeout=9)
    print "}"
    get_result_table_syn_scan(ans)

def get_result_syn_scan_atom(targets,ports):
    aux_result_table = []
    for i in targets:
        print "# Escanenado [",i,"] #"
        aux = syn_scan_for_host(i,ports)
        aux_result_table.append(aux)

def split_params(param):
    res =[]
    if param.find("/") != -1:
        res = get_ip_range(param)
    elif param.find("-") != -1:
        res = get_port_range(param)
    elif param.find("*65536") != -1:
        res = get_list_all_ports()
        print "=????Z>>> ",res
    else:
        if param.find(",") != -1:
            res_aux = param.split(",")
            if "." not in res_aux[0]:
                for i in res_aux:
                    res.append(int(i))
            else:
                res = res_aux
        else:
            if "." not in param:
                res.append(int(param))
            else:
                res.append(param)
    return res

def scan_host_ICMP(targets):
    for i in targets:
        print "#######################"
        print "# Escaneando [",i,"] #"
        print "{"
        p = IP(dst=i)/ICMP()
        ans, nans= sr(p, timeout=9)
        print "}"
        print_ICMP_result(ans)
        print "#######################"

def print_ICMP_result(server_response):
    if len(server_response[ICMP]) != 0:
        print "························"
        print "· El host está activo  ·"
        print "························"
    else:
        print "························"
        print "·El host está inactivo·"
        print "························"

def get_list_ports_default():
    res =[]
    for i in range(1,1001):
        res.append(i)
    return res

def get_list_all_ports():
    res =[]
    for i in range(1,65536):
        res.append(i)
    return res

def get_ip_range(ip_range):
    res = []
    aux = ip_range.split("/")
    pref = str(aux[0].split(".")[0]) + "." + str(aux[0].split(".")[1]) + "." +str(aux[0].split(".")[2]) + "." 
    for i in range(1,255):
        res.append(pref + str(i))
    return res

def get_port_range(number_range):
    res = []
    aux = number_range.split("-")
    start = int(aux[0])
    end = int(aux[1])
    for i in range(start, end):
        res.append(int(i))
    return res

main()
