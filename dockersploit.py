#!/usr/bin/env python3
import re
import os
import sys
import json
import docker
import pathlib
import argparse
import subprocess
from time import sleep

docker_path = 'templates/'
path = str(pathlib.Path(__file__).parent.resolve())

# Read stats from the vulnerable container
def read_stats(id):
    client = docker.from_env()
    res = []
    if is_dockerfile(id):
        res.append(client.containers.get("dockersploit-" + str(id.lower())))
    else:
        c = client.containers.list(all=True)
        for i in c:
            if id.lower() in i.attrs["Name"][1:]:
                res.append(i)
    sleep(1)
    ids = []
    names = []
    mem_usages = 0
    cpu_percent = 0.0
    mem_percent = 0.0
    for container in res:
            d = container.stats(stream=False)
	    #Count CPU usage percentage
            ids.append(d["id"][:10])
            names.append(d["name"].strip("/"))
            mem_usages += d["memory_stats"]["usage"]
            cpu_count = d["cpu_stats"]["online_cpus"]
            cpu_percent = 0.0
            cpu_delta = float(d["cpu_stats"]["cpu_usage"]["total_usage"]) - \
                float(d["precpu_stats"]["cpu_usage"]["total_usage"])
            system_delta = float(d["cpu_stats"]["system_cpu_usage"]) - \
	        float(d["precpu_stats"]["system_cpu_usage"])
            if system_delta > 0.0:
                cpu_percent += (cpu_delta / system_delta * 100.0 * cpu_count)

	    #Count memory usage percentage
            mem_used = d["memory_stats"]["usage"] + d["memory_stats"]["stats"]["active_file"]
            limit = d['memory_stats']['limit']
            mem_percent += (round(mem_used / limit * 100, 2))
    return cpu_percent, mem_percent, ", ".join(ids), ", ".join(names), mem_usages, d["memory_stats"]["limit"]

def check_permissions():
    """
    Check permission from the user
    """
    if os.getuid() != 0 and "docker" not in os.popen("/usr/bin/groups").read():
        print("[!] Please run the script using sudo or make sure you are in the docker group!")
        exit()

def listc(val=0, cve=""):
    """
    List running containers from dockersploit.
    """
    client = docker.from_env()
    res = client.containers.list(all=True)
    r = []
    if val == 0:
        for container in res:
            if container.name.startswith("dockersploit-"):
                r.append(container)
        if not r:
            print("[+] There is no dockersploit container running.")
        else:
            for container in r:
                print("[+] " + container.name[13:].upper() + " container is running.")
    elif val == 1:
        for container in res:
            if container.name.startswith(f"dockersploit-{cve.lower()}"):
                r.append(container.name)
        return r
    elif val == 3:
        for container in res:
            if container.name.startswith(f"dockersploit-{cve.lower()}"):
                r.append(container)
        return r

def read_running():
    ipadd = {}
    ports = {}
    with open(path + "/.running", "r") as f:
        for line in f.readlines():
            id,ip,port = line.strip().split("==")
            ipadd[id] = ip
            ports[id] = port
    f.close()
    return ipadd, ports

def is_container_running(cve):
    container = listc(1, cve)
    if not container:
        pass
    else:
        print("Container is currently running or is not yet removed. Exiting...")
        exit()

def listCVE():
    """
    List avaiable CVEs to be simulated.
    """
    docker_lists = read_json(".data.json","", "", 2)
    docker_list = [i for i in docker_lists]

    print("[+] CVEs available for dockersploit: ")
    save_result(docker_list)
    for i in range(len(docker_list)):
        print(f"{i+1}. {docker_list[i]}")
    return docker_list
    

def delete(arg):
    """
    Stop and remove a running container from dockersploit.
    """
    client = docker.from_env()
    cve = arg
    docker_name = ''

    pattern = re.compile("^(CVE|cve)-[0-9]{4}-[0-9]{4,7}(-[a-zA-Z]{1,5})?$")
    pattern2 = re.compile("^[0-9]{1,3}$")

    if pattern.match(cve):
        docker_name = cve.upper()
    elif pattern2.match(cve):
        val = int(cve)
        tmp_result = path + "/.tmp-result"
        res = read_result(tmp_result)
        if val < 0 or val > len(res):
            print("[-] Docker does not exist")
            exit()
        else:
            docker_name = res[int(cve)-1]
            inp = input(f"Do you want to delete {docker_name}? [y/N]")
            if inp.strip().startswith('N'):
                print("Good bye!")
                exit()
    else:
        exit()
    
    to_be_deleted_container = listc(1, docker_name)
    if not to_be_deleted_container:
        print(f"[+] The {docker_name} container is not running or doesn't exist.")
    else:
        for deleted_container in to_be_deleted_container:
            c = client.containers.get(deleted_container)
            if not listc(3, docker_name):
                pass
            else:
                c.kill()
            c.remove()
            
            # Delete CVE ID from .running
            with open(path + "/.running", "r+") as f:
                lines = f.readlines()
                f.seek(0)
                for line in lines:
                    if docker_name != line.split("==")[0].strip():
                        f.write(line)
                f.truncate()
                
            print(f"[+] The {deleted_container} container has been removed.")

def is_dockerfile(path):
    """
    Check if the CVE is using Dockerfile.
    """
    if os.path.exists(path + "docker-compose.yml"):
        return 0
    elif os.path.exists(path + "Dockerfile"):
        return 1

def check_cve(cve):
    """
    Check if the CVE is available.
    """
    docker_lists = read_json(".data.json","", "", 2)
    if cve.upper() in docker_lists:
        pass
    else:
        print(f"{cve.upper()} isn't available or doesn't exist!")
        exit()

def cve(args):
    """
    Build the docker image from the dockerfile or using docker compose.
    """
    
    cve = args
    fname = '.data.json'

    # Check the user input for the proper CVE format.
    pattern = re.compile("^(CVE|cve)-[0-9]{4}-[0-9]{4,7}$")
    pattern2 = re.compile("^[0-9]{1,3}$")

    if pattern.match(cve):
        docker_name = cve.upper()
    elif pattern2.match(cve):
        val = int(cve)
        tmp_result = path + "/.tmp-result"
        res = read_result(tmp_result)
        if val < 0 or val > len(res):
            print("[-] The CVE does not exist")
            exit()
        else:
            docker_name = res[int(args)-1]
            inp = input(f"Do you want to run {docker_name}? [y/N]")
            if inp.strip().startswith('N'):
                print("Good bye!")
                exit()
    else:
        exit()

    dockerfile_path = path + "/" + docker_path + "/" + docker_name +"/"

    # Check if the CVE is available or not.
    check_cve(docker_name)
	
    # Check if the CVE is already running or not
    is_container_running(docker_name)
    
    # Run the CVE using Dockerfile
    if is_dockerfile(dockerfile_path):
        final_path = dockerfile_path + "Dockerfile"
        dockerfile_content = open(final_path, 'r').readlines()

        tmp = 1
        servicesPort = {}
        for val in dockerfile_content:
            val = val.strip()
            if 'EXPOSE ' in val:
                port = val[7:].strip()
                service = dockerfile_content[tmp][2:].strip()
                servicesPort[port] = service
            tmp += 1
        if servicesPort == {}:
            servicesPort["privesc"] = "flag"
        # Build the container from the Dockerfile
        cli = docker.APIClient()
        print(f"[+] Building the {docker_name} container.")
        flag = 0
        nothing = """{"stream":"\\n"}"""
        for line in cli.build(path=dockerfile_path, dockerfile="Dockerfile", rm=True, tag=f'dockersploit-{docker_name.lower()}'):
            if line.decode().strip() != nothing:
                if "--->" not in line.decode('unicode_escape').strip():
                    try :
                        d = eval(line.decode('unicode_escape').strip())
                        if d["status"] == "Downloading" or d["status"] == "Extracting":
                            flag = 1
                            sys.stdout.write('\r  \r')
                            sys.stdout.write(d["status"] + " : " + d["progress"].strip())
                            sys.stdout.flush()
                    except:
                        if flag == 1:
                            print()
                        r = line.decode('unicode_escape').strip()
                        try:
                            res = eval(r)
                            print(res["stream"])
                        except:
                            pass
                        flag = 0
        print()
        port_dict = {}
        # Run the container
        client = docker.from_env()
        client.api.create_host_config
        for line in dockerfile_content:
            if "EXPOSE " in line:
                port_dict[int(line[7:])] = ('127.0.0.1',None)

        print(f"[+] Starting the {docker_name} container.")
        container = client.containers.run(f'dockersploit-{docker_name.lower()}', tty=True, detach=True, name=f"dockersploit-{docker_name.lower()}", ports=port_dict)
        container.reload()
        p = container.ports
        port_list = []
        for port in p.keys():
            port_list.append(port)
        container = client.containers.get(f"dockersploit-{docker_name.lower()}")
        ip_add = container.attrs['NetworkSettings']['IPAddress']
        if "privesc" in servicesPort.keys():
            print(f"[+] The {docker_name} container can be accessed through these commands:")
            print(f"docker exec -it {container.id[:5]} /bin/sh")
        else:
            print(f"[+] The {docker_name} container can be accessed at 127.0.0.1 through these service(s) and port(s):")
            for port in port_list:
                print(f"{p[port][0]['HostPort']} -> {port} {servicesPort[port.split('/')[0]]}")
    
    # Run the CVE using docker compose.
    else:
        p = ""
        port_list= ""
        final_path = dockerfile_path + "docker-compose.yml"
        dockerfile_content = open(final_path, 'r').readlines()
        tmp = 1
        ip_add = "127.0.0.1"
        servicesPort = {}
        for val in dockerfile_content:
            val = val.strip()
            if 'EXPOSE ' in val:
                port = val[9:].strip()
                service = dockerfile_content[tmp].strip()[2:]
                servicesPort[port] = service
            tmp += 1

        os.chdir(dockerfile_path)
        if os.name == "posix":
            process = subprocess.Popen(['docker','compose', 'up', '-d'], stdout=subprocess.PIPE)
            for c in iter(lambda: process.stdout.read(1), b""):
                sys.stdout.buffer.write(c)
            print()
        elif os.name == "nt":
            rocess = subprocess.Popen(['docker-compose', 'up', '-d'], stdout=subprocess.PIPE)
            for c in iter(lambda: process.stdout.read(1), b""):
                sys.stdout.buffer.write(c)
            print()
        else:
            print("The current operating system is not supported! Exiting...")
            sys.exit(0)
        print("The container can be accessed at 127.0.0.1 through these ports:")
        for key in servicesPort:
           print(f"{servicesPort[key]} on port {key}")
    
    # Print the CVE details.
    details = read_json(fname, docker_name, "references", 1)
    print("-----------------------")
    print(f"Name: {details['name']}")
    print(f"Description: {details['description']}")
    print(f"Score: {details['score']}")
    print(f"Severity: {details['severity']}")
    print("References: ")
    for i in range(len(details['references'])):
        print(f"\t{i+1} - {details['references'][i]}")
    print("-----------------------")
    # Append CVE ID and IP to .running
    running = open(path + "/.running" , "a")
    if os.name == "posix":
        if p != "" and port_list != "":
            l = {}
            for a in port_list:
                b = a.split("/")[0]
                l[str(p[a][0]['HostPort'])] = str(a) + " " + str(servicesPort[b])
            running.write(docker_name + "==" + ip_add  + "==" + str(l) + "\n")
        else:    
            running.write(docker_name + "==" + ip_add  + "==" + str(servicesPort) + "\n")
    else:
        if p != "" and port_list != "":
            l = {}
            for a in port_list:
                b = a.split("/")[0]
                l[str(p[a][0]['HostPort'])] = str(a) + " " + str(servicesPort[b])
            running.write(docker_name + "==" + ip_add  + "==" + str(l) + "\n")
        else:
            running.write(docker_name + "==" + ip_add  + "==" + str(servicesPort))
    running.close()

def run_web():
    """
    Run the GUI web application.
    """
    from web import app as gui
    gui.app.run(debug=False)

def read_json(file_name, user_input, key, value=0):
    """
    Read the JSON data from .data.json file
    """
    f = open(path + "/" + file_name)
    res = json.load(f)
    cve_number = res.keys()

    valid_cve = []
    
    # Default search
    if value == 0:
        keys = ["name","description","tags"]
        for cve in cve_number:
            if cve.startswith(user_input.upper()):
                valid_cve.append(cve)
                continue
            for key in keys:
                if user_input in str(res[cve][key]):
                    valid_cve.append(cve)
        return list(set(valid_cve))
    elif value == 1: # return details json data
        keys = ["name", "description", "score", "severity", "references"]
        details = {}
        for key in keys:
            details[key] = res[user_input][key]
        return details
    elif value == 2: # Check if cve is available
        return cve_number
    elif value == 3: # tag
        for cve in cve_number:
            if user_input in str(res[cve][key]):
                valid_cve.append(cve)
        return return list(set(valid_cve))

def save_result(result):
    fname = '.tmp-result'
    with open(fname, 'w+') as f:
        for i in result:
            f.writelines(i+"\n")

def read_result(fname):
    res = []
    with open(fname, 'r') as f:
        res = f.readlines()
    return [i.strip() for i in res]

def search(arg):
    """
    Search for existing CVEs through its name, description and tags.
    """
    fname = ".data.json"

    if arg.startswith("severity:"):
        res = read_json(fname,arg[9].upper() + arg[10:], arg[:8], 3)
    
    elif arg.startswith("year:"):
        res = read_json(fname, arg[5:], arg[:4], 3)

    elif arg.startswith("score:"):
        res = read_json(fname, str(float(arg[6:])), arg[:5], 3)
    
    else:
        res = read_json(fname, arg, "")

    if res:
        save_result(res)
        for i in range(len(res)):
            print(f"{i+1}. {res[i]}")
    return res
    

def checkhelp():
    """
    Check all arguments passed by the user.
    """
    check = ['--cve','--delete','--list','-d','-l','-c','-h','--help']
    parser = argparse.ArgumentParser(description="Dockersploit")
    parser.add_argument("-ps","--process", action='store_true',help="List all running dockersploit container[s].")
    parser.add_argument("-d","--delete",help="Delete a running dockersploit container by supplying the CVE code of the container.")
    parser.add_argument("-c","--cve",help="CVE number to be simulated by supplying the CVE code to be simulated.")
    parser.add_argument("-s","--search",help="Search for CVEs available on Dockersploit.")
    parser.add_argument("-l","--list", action='store_true', help="List available CVEs to be simulated.")
    parser.add_argument("-w","--web", action='store_true', help="Run a GUI web application for Dockersploit.")

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)
    return parser.parse_args()

def main():
    if os.name == "posix":
        check_permissions()
    arg = checkhelp()
    if arg.web != False:
        run_web()
    if arg.list != False:
        listCVE()
    if arg.delete != None:
        delete(arg.delete)
    if arg.cve != None:
        cve(arg.cve)
    if arg.process != False:
        listc()
    if arg.search != None:
        res = search(arg.search)
        if res == []:
            print("No CVE in our catalog matches your search!")

if __name__ == '__main__':
    main()
