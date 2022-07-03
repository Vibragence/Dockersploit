#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect
import pathlib
import sys
import json
import os
import ast
path = str(pathlib.Path(__file__).parent.resolve())
sys.path.insert(1, path + "/../")
import dockersploit
import string
import random

# Read .data.json
path = str(pathlib.Path(__file__).parent.resolve())
f = open(f"{path}/../.data.json")
cveDict = json.load(f)

#create the object of Flask
app  = Flask(__name__)

@app.route('/', methods= ["GET"])
def index():
    cve_number = request.args.get("cve_number")
    running, ports = dockersploit.read_running()
    d = {}
    for cve in ports.keys():
        d[cve] = eval(ports[cve])
    ports = d
    if request.args.get("run"):
        run = request.args.get("run")
        return render_template('tables.html', cve_number = cve_number, cveDict = cveDict, run = run, running = running, ports = ports)
    elif request.args.get("delete"):
        delete = request.args.get("delete")
        return render_template('tables.html', cve_number = cve_number, cveDict = cveDict, delete = delete, running = running, ports = ports)
    else:
        return render_template('tables.html', cve_number = cve_number, cveDict = cveDict, running = running, ports = ports)

@app.route('/run', methods = ["GET"])
def run_docker():
   cve_number = request.args.get("cve_number")
   dockersploit.cve(str(cve_number))
   return redirect("http://127.0.0.1:5000/details?cve_number="+cve_number, code=302)

@app.route('/listCVE')
def list_cve():
   return dockersploit.listCVE()

@app.route('/listRunningContainer')
def Running():
   return dockersploit.listc()

@app.route('/delete', methods = ["GET"])
def Delete():
   cve_number = request.args.get("cve_number")
   dockersploit.delete(str(cve_number))
   return redirect("http://127.0.0.1:5000/?delete=true&cve_number="+cve_number, code=302)

@app.route('/search', methods = ["GET"])
def Search():
    query = str(request.args.get("q"))
    res = dockersploit.search(query)
    cve_number = request.args.get("cve_number")
    running, ports = dockersploit.read_running()
    if not res:
        return render_template('tables.html', cve_number = cve_number, cveDict = {}, running = running)
    else:
        cve_dict = {}
        for cve in res:
            cve_dict[cve] = {}
            cve_dict[cve]['name'] = cveDict[cve]['name']
            cve_dict[cve]['description'] = cveDict[cve]['description']
            cve_dict[cve]['score'] = cveDict[cve]['score']
            cve_dict[cve]['severity'] = cveDict[cve]['severity']
            cve_dict[cve]['references'] = cveDict[cve]['references']
            cve_dict[cve]['year'] = cveDict[cve]['year']
            cve_dict[cve]['tags'] = cveDict[cve]['tags']
        return render_template('tables.html', cve_number = cve_number, cveDict = cve_dict, running = running)

@app.route('/details', methods = ["GET"])
def Details():
    cve_number = request.args.get("cve_number")
    running, ports = dockersploit.read_running()
    c = cveDict[cve_number]
    if cve_number in ports.keys():
        port_list = ast.literal_eval(ports[cve_number])
        cpu, mem, docker_id, docker_name, mem_usage, limit = dockersploit.read_stats(cve_number)
        cpu_format = "{:.2f}".format(cpu)
        return render_template("details.html", c = c, cve_number = cve_number, running = running, port_list = port_list, cpu = cpu_format, mem = mem, docker_id = docker_id, docker_name = docker_name, started=True, mem_usage = "{:.2f}".format((mem_usage/1000000)), limit = "{:.2f}".format((limit/1000000)))
    else:
        return render_template("details.html", c = c, cve_number = cve_number, started=False)
    
@app.route('/about')
def About():
    return render_template("about.html")
    
@app.route('/usage', methods = ["GET"])
def Usage():
    cve_number = request.args.get("c")
    letters = string.ascii_lowercase
    cpu,ram,c_id,name, mem_usage, ram_limit = dockersploit.read_stats(cve_number)
    cpu_format = "{:.2f}".format(cpu)
    mem = "{:.2f}".format((mem_usage/1000000))
    limit = "{:.2f}".format((ram_limit/1000000))
    return str(cpu_format) + "," + str(ram/2) + "," + str(mem) + "," + str(limit)

#run flask app
if __name__ == "__main__":
    app.run()
