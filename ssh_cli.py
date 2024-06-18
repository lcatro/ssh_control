
import argparse
import csv
import os
import queue
import random
import socket
import sys
import time

from threading import Thread

import logging
logging.getLogger('paramiko').setLevel(logging.CRITICAL)

import paramiko

from tqdm import tqdm


class remote_ssh:

    SSH_SUCCESS = 0x00
    SSH_AUTH_FAIL = 0x01
    SSH_TIMEOUT = 0x02
    SSH_UNKNOW = 0xFF

    def __init__(self,ip,username,password):
        self.remote_ip = ip
        self.ssh_username = username
        self.ssh_password = password

    def upload_file_with_ssh(self,local_file_path,remote_file_path):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(hostname=self.remote_ip, port=22, username=self.ssh_username, password=self.ssh_password,timeout=10)

            sftp = client.open_sftp()
            print(sftp.put(local_file_path, remote_file_path))
        except paramiko.ssh_exception.AuthenticationException:
            return remote_ssh.SSH_AUTH_FAIL
        except paramiko.ssh_exception.SSHException:
            return remote_ssh.SSH_TIMEOUT
        except socket.timeout:
            return remote_ssh.SSH_TIMEOUT
        except:
            return remote_ssh.SSH_UNKNOW

        return remote_ssh.SSH_SUCCESS

    def download_file_with_ssh(self,local_file_path,remote_file_path):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(hostname=self.remote_ip, port=22, username=self.ssh_username, password=self.ssh_password,timeout=10)
        
            sftp = client.open_sftp()
            sftp.get(remote_file_path, local_file_path)
            
            sftp.close()
            client.close()
        except paramiko.ssh_exception.AuthenticationException:
            return remote_ssh.SSH_AUTH_FAIL
        except paramiko.ssh_exception.SSHException:
            return remote_ssh.SSH_TIMEOUT
        except socket.timeout:
            return remote_ssh.SSH_TIMEOUT
        except:
            return remote_ssh.SSH_UNKNOW

        return remote_ssh.SSH_SUCCESS

    def command_with_ssh(self,command):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(hostname=self.remote_ip, port=22, username=self.ssh_username, password=self.ssh_password,timeout=10)
        
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read()
            try:
                output = output.decode('utf-8')
            except:
                output = output.decode('gbk')
            #error = stderr.read().decode('utf-8')

            client.close()
        except paramiko.ssh_exception.AuthenticationException:
            return remote_ssh.SSH_AUTH_FAIL,''
        except paramiko.ssh_exception.SSHException:
            return remote_ssh.SSH_TIMEOUT,''
        except socket.timeout:
            return remote_ssh.SSH_TIMEOUT,''
        except:
            return remote_ssh.SSH_UNKNOW,''

        return remote_ssh.SSH_SUCCESS,output
    
    def command_with_ssh_background(self,command):
        thread_imp = Thread(target=remote_ssh.command_with_ssh,args=(self,command))
        thread_imp.daemon = True
        thread_imp.start()
    

class csv_loader:

    def __init__(self,csv_list_data):
        self.csv_list_data = csv_list_data

    def factory(metadata_file_path,is_random):
        data = []

        with open(metadata_file_path, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)

            for row in reader:
                data.append(row)

        if is_random:
            random.shuffle(data)

        return csv_loader(data)

    def factory_with_resume(metadata_file_path,resume_task_data):
        return csv_loader(resume_task_data)

    def factory_with_new(data):
        return csv_loader(data)

    def get_items(self):
        return self.csv_list_data
    
    def get_size(self):
        return len(self.csv_list_data)

    def get_queue(self):
        result = queue.Queue()

        for csv_data in self.csv_list_data:
            result.put(csv_data)

        return result
    
    def get_random_item_with_time(self,time_range):   #   给定一个时间范围,在这个范围内随机分配任务
        random_task = []

        for csv_item in self.csv_list_data:
            random_task.append((random.randint(0,time_range),csv_item))
            
        return random_task

    def filter_by_data(self,filter_exp_list):
        result = []

        for csv_col in self.csv_list_data:
            for filter_exp in filter_exp_list:
                is_bingo = True

                for key,value in filter_exp.items():
                    if not key in csv_col:
                        is_bingo = False
                        break
                    
                    if not csv_col[key] == value:
                        is_bingo = False
                        break

                if is_bingo:
                    result.append(csv_col)

        return csv_loader(result)

class csv_writer:

    def __init__(self,save_file_path):
        self.save_file_path = save_file_path
        self.data_list = []
        self.fields_list = []
        self.file = open(self.save_file_path,'w',newline='')
        self.writer = csv.DictWriter(self.file, fieldnames=self.fields_list)

    def factory(save_file_path):
        return csv_writer(save_file_path)

    def init_data(self,data_list):
        self.data_list = data_list
        all_fields = []

        for data_item in self.data_list:
            key_list = list(data_item.keys())

            for key in key_list:
                if not key in all_fields:
                    all_fields.append(key)
            
        self.fields_list = all_fields

    def append_data(self,data_item):
        key_list = list(data_item.keys())
        new_keys = [x for x in key_list if x not in self.fields_list]

        if new_keys:
            self.fields_list += new_keys

        self.data_list.append(data_item)

    def save_data(self):
        with open(self.save_file_path,'w',newline='') as file:
            writer = csv.DictWriter(file, fieldnames=self.fields_list)

            writer.writeheader()

            for json_data in self.data_list:
                writer.writerow(json_data)

        
def ssh_thread(ip,username,password,command,pipe):
    ssh_object = remote_ssh(ip,username,password)
    ssh_status,result = ssh_object.command_with_ssh(command)

    pipe.put((ip,ssh_status,result))

def ssh_upload_thread(ip,username,password,local_file,remote_file,pipe):
    ssh_object = remote_ssh(ip,username,password)
    ssh_status = ssh_object.upload_file_with_ssh(local_file,remote_file)

    pipe.put((ip,ssh_status))


show_match_ip = False
show_ignore_ip = False
show_timeout_ip = False
show_unknow_ip = False
enable_match_result = False
enable_ignore_result = False
show_output = False
show_auth_fail_ip = False


def execute_ssh(csv_file_data,arg_username,arg_password,thread_num,str_match,re_match,command):
    global show_match_ip,enable_match_result,enable_ignore_result,show_auth_fail_ip,show_output

    thread_list = []
    thread_output_pipe = queue.Queue()
    auth_fail_list = []
    ssh_timeout_list = {}
    all_ssh_result = {}
    unknow_ip_list = []

    if command == 'mutilline' or command == 'mtl':
        print('mutilline Command>>>',end=' ')
        command = input()

    with tqdm(total=csv_file_data.get_size(),desc='SSH Process', unit=" ExecuteCommand") as pbar:
        all_data = csv_file_data.get_items()
        line_index = 0
        
        while line_index < len(all_data):
            line_data = all_data[line_index]
            ip = line_data.get('ip','')
            username = line_data.get('username','')
            password = line_data.get('password','')
            line_index += 1

            if not ip:
                print('No Fidle ip')
                break
            
            if not username:
                username = arg_username
            if not password:
                password = arg_password

            execute_command = command

            for command_variant,command_value in line_data.items():
                execute_command = execute_command.replace('%%{%s}' % (command_variant),command_value)

            thread_object = Thread(target=ssh_thread,args=(ip,username,password,execute_command,thread_output_pipe))
            thread_object.daemon = True
            thread_object.start()
            thread_list.append(thread_object)

            if len(thread_list) >= thread_num or line_index >= len(all_data) - 1:
                for thread_index in thread_list:
                    thread_index.join(300)

                thread_list = []

            while thread_output_pipe.qsize():
                ip,ssh_status,ssh_result = thread_output_pipe.get()

                pbar.update(1)

                if ssh_status == remote_ssh.SSH_SUCCESS:
                    if ip in ssh_timeout_list:
                        ssh_timeout_list.pop(ip)

                    if args.show_output:
                        print('Execute Result',ip,'==>',ssh_result)

                    all_ssh_result[ip] = ssh_result
                elif ssh_status == remote_ssh.SSH_AUTH_FAIL:
                    if ip in ssh_timeout_list:
                        ssh_timeout_list.pop(ip)

                    auth_fail_list.append(ip)
                elif ssh_status == remote_ssh.SSH_TIMEOUT:
                    if not ip in ssh_timeout_list:
                        ssh_timeout_list[ip] = 0

                    if ssh_timeout_list[ip] <= 3:
                        ssh_timeout_list[ip] += 1
                        pbar.total += 1

                        thread_object = Thread(target=ssh_thread,args=(ip,username,password,command,thread_output_pipe))
                        thread_object.daemon = True
                        thread_object.start()
                        thread_list.append(thread_object)
                elif ssh_status == remote_ssh.SSH_UNKNOW:
                    unknow_ip_list.append(ip)

                    
    for thread_index in thread_list:
        thread_index.join(300)

    thread_list = []
            
    if all_ssh_result:
        print('===== SSH Success (%d) =====' % (len(all_ssh_result)))

        if show_match_ip:
            for ip in all_ssh_result.keys():
                print(ip)


    if auth_fail_list:
        print('===== SSH Auth Fail (%d) =====' % (len(auth_fail_list)))

        if show_auth_fail_ip:
            for ip in auth_fail_list:
                print(ip)

    if ssh_timeout_list:
        print('===== SSH Timeout (%d) =====' % (len(ssh_timeout_list)))

        if show_timeout_ip:
            for ip in list(ssh_timeout_list.keys()):
                print(ip)

    if unknow_ip_list:
        print('===== SSH Unknow Except (%d) =====' % (len(unknow_ip_list)))

        if show_unknow_ip:
            for ip in unknow_ip_list:
                print(ip)
                
    match_ip_list = []
    ignore_ip_list = []
    all_bingo_result = {}
    all_nobingo_result = {}

    if str_match:

        for ip,ssh_result in all_ssh_result.items():
            if not str_match in ssh_result:
                all_nobingo_result[ip] = ssh_result
                continue

            all_bingo_result[ip] = ssh_result

        print('===== SSH Str Match Bingo:%d =====' % (len(all_bingo_result)))

        for ip,ssh_result in all_bingo_result.items():
            match_ip_list.append({'ip':ip})

            if enable_match_result:
                print(' Str Match >>',ip,ssh_result)
            elif show_match_ip:
                print(ip)
                
        print('===== SSH Str Match Ignore:%d =====' % (len(all_nobingo_result)))
        for ip,ssh_result in all_nobingo_result.items():
            ignore_ip_list.append({'ip':ip})

            if enable_ignore_result:
                print(' Str Ignore >>',ip,ssh_result)
            elif show_ignore_ip:
                print(ip)
                
    return match_ip_list,ignore_ip_list,all_ssh_result,all_bingo_result,all_nobingo_result

def upload_ssh(ip_list,arg_username,arg_password,thread_num,local_file_path,remote_file_path):
    global show_match_ip,enable_match_result,enable_ignore_result,show_auth_fail_ip,show_output

    thread_list = []
    thread_output_pipe = queue.Queue()
    auth_fail_list = []
    ssh_timeout_list = {}
    all_ssh_result = {}
    unknow_ip_list = []
    
    with tqdm(total=len(ip_list),desc='SSH Process', unit=" UploadFile") as pbar:
        line_index = 0
        
        while line_index < len(ip_list):
            ip = ip_list[line_index]
            line_index += 1

            if not ip:
                print('No Fidle ip')
                break
            
            pbar.total += 1

            thread_object = Thread(target=ssh_upload_thread,args=(ip,arg_username,arg_password,local_file_path,remote_file_path,thread_output_pipe))
            thread_object.daemon = True
            thread_object.start()
            thread_list.append(thread_object)
            
            if len(thread_list) >= thread_num or line_index >= len(ip_list) - 1:
                for thread_index in thread_list:
                    thread_index.join(300)

                thread_list = []

            while thread_output_pipe.qsize():
                ip,ssh_status = thread_output_pipe.get()

                pbar.update(1)

                if ssh_status == remote_ssh.SSH_SUCCESS:
                    if ip in ssh_timeout_list:
                        ssh_timeout_list.pop(ip)

                    if args.show_output:
                        print('Upload Result',ip,'==>',ssh_status)

                    all_ssh_result[ip] = True
                elif ssh_status == remote_ssh.SSH_AUTH_FAIL:
                    if ip in ssh_timeout_list:
                        ssh_timeout_list.pop(ip)

                    auth_fail_list.append(ip)
                elif ssh_status == remote_ssh.SSH_TIMEOUT:
                    if not ip in ssh_timeout_list:
                        ssh_timeout_list[ip] = 0

                    if ssh_timeout_list[ip] <= 3:
                        ssh_timeout_list[ip] += 1
                        pbar.total += 1

                        thread_object = Thread(target=ssh_upload_thread,args=(ip,username,password,local_file_path,remote_file_path,thread_output_pipe))
                        thread_object.daemon = True
                        thread_object.start()
                        thread_list.append(thread_object)
                elif ssh_status == remote_ssh.SSH_UNKNOW:
                    unknow_ip_list.append(ip)

 
    for thread_index in thread_list:
        thread_index.join(300)

    thread_list = []
            
    if all_ssh_result:
        print('===== SSH Success (%d) =====' % (len(all_ssh_result)))

        if show_match_ip:
            for ip in all_ssh_result.keys():
                print(ip)


    if auth_fail_list:
        print('===== SSH Auth Fail (%d) =====' % (len(auth_fail_list)))

        if show_auth_fail_ip:
            for ip in auth_fail_list:
                print(ip)

    if ssh_timeout_list:
        print('===== SSH Timeout (%d) =====' % (len(ssh_timeout_list)))

        if show_timeout_ip:
            for ip in list(ssh_timeout_list.keys()):
                print(ip)

    if unknow_ip_list:
        print('===== SSH Unknow Except (%d) =====' % (len(unknow_ip_list)))

        if show_unknow_ip:
            for ip in unknow_ip_list:
                print(ip)
                

def result_preprocess():
    pass


def save_result_to_file(file_path,save_data):
    print('ssh result save file',file_path)
    csv_file = csv_writer.factory(file_path)

    for ip,ssh_result in save_data.items():
        csv_file.append_data({
            'ip': ip,
            'result': ssh_result
        })
        
    csv_file.save_data()


if __name__ == '__main__':
    start_time = time.time()

    if len(sys.argv) < 2:
        print('./launchpad-ssh-cli.py run')
        print('./launchpad-ssh-cli.py download')
        print('./launchpad-ssh-cli.py upload')
        exit()
        
    if sys.argv[1] == 'upload':
        parser = argparse.ArgumentParser(description='upload')
        parser.add_argument('upload')
        parser.add_argument('--thread', dest='thread',default=1,type=int, help='thread num for execute ssh')
        parser.add_argument('--csv_file', dest='csv_file',default='',type=str, help='csv data')
        parser.add_argument('--ip', dest='ip',default='',type=str, help='ip')
        parser.add_argument('--username', dest='username',default='ubuntu',type=str, help='username')
        parser.add_argument('--password', dest='password',default='root',type=str, help='password')
        parser.add_argument('-v', dest='show_output',action='store_true', help='no show ssh output')
        parser.add_argument('local_path', help='Local File to Upload')
        parser.add_argument('remote_path', help='Save File at Server')
        args = parser.parse_args()

        thread_num = args.thread
        username = args.username
        password = args.password
        local_path = args.local_path
        remote_path = args.remote_path
        
        ip = args.ip
        ip_list = []

        if ip:
            if os.path.exists(ip):
                ip_file = open(ip)
                data_list = ip_file.readlines()
                ip_file.close()
                ip_list = []
            else:
                ip_list = [ip]
        else:
            print('No Found IP')
            exit()


        upload_ssh(ip_list,username,password,thread_num,local_path,remote_path)

        print('Using Time %.2fs' % (time.time() - start_time))
    elif sys.argv[1] == 'run':
        parser = argparse.ArgumentParser(description='run')
        parser.add_argument('run')
        parser.add_argument('--thread', dest='thread',default=1,type=int, help='thread num for execute ssh')
        parser.add_argument('--csv_file', dest='csv_file',default='',type=str, help='csv data')
        parser.add_argument('--ip', dest='ip',default='',type=str, help='ip')
        parser.add_argument('--username', dest='username',default='ubuntu',type=str, help='username')
        parser.add_argument('--password', dest='password',default='root',type=str, help='password')
        parser.add_argument('--match', dest='match',default='',type=str, help='match ssh result')
        parser.add_argument('--rematch', dest='rematch',default='',type=str, help='re-match ssh result')
        parser.add_argument('--show_auth_fail_ip', dest='show_auth_fail_ip',action='store_true',help='show auth fail ip')
        parser.add_argument('--show_match_ip', dest='show_match_ip',action='store_true',help='show all match ip list')
        parser.add_argument('--show_ignore_ip', dest='show_ignore_ip',action='store_true',help='show all ignore ip list')
        parser.add_argument('--show_timeout_ip', dest='show_timeout_ip',action='store_true',help='show timeout ip list')
        parser.add_argument('--show_unknow_ip', dest='show_unknow_ip',action='store_true',help='show unknow except ip list')
        parser.add_argument('--enable_match_result', dest='enable_match_result',action='store_true',help='show match ssh output result')
        parser.add_argument('--enable_ignore_result', dest='enable_ignore_result',action='store_true',help='show ignore ssh output result')
        parser.add_argument('-v', dest='show_output',action='store_true', help='no show ssh output')
        parser.add_argument('--save', dest='save',default='',type=str, help='save ssh result to file')
        parser.add_argument('--save_match', dest='save_match',action='store_true',help='save match result')
        parser.add_argument('--save_ignore', dest='save_ignore',action='store_true',help='save ignore result')
        parser.add_argument('--result_exp', dest='result_exp',default='',type=str, help='result process express')
        parser.add_argument('command', help='SSH Execute Command')

        args = parser.parse_args()
        cvs_file = args.csv_file

        if cvs_file:
            csv_file_data = csv_loader.factory(cvs_file,False)
        else:
            ip = args.ip

            if ip:
                if os.path.exists(ip):
                    ip_file = open(ip)
                    data_list = ip_file.readlines()
                    ip_file.close()
                    ip_list = []

                    for ip_record in data_list:
                        ipdata = ip_record.strip()

                        if not ipdata:
                            continue

                        ip_list.append({
                            'ip': ipdata
                        })

                    csv_file_data = csv_loader.factory_with_new(ip_list)
                else:
                    csv_file_data = csv_loader.factory_with_new([{
                        'ip': ip,
                    }])
            else:
                print('No IP Data in --csv_file and --ip')
                exit()

        command = args.command
        str_match = args.match
        re_match = args.rematch
        thread_num = args.thread
        show_match_ip = args.show_match_ip
        show_ignore_ip = args.show_ignore_ip
        show_auth_fail_ip = args.show_auth_fail_ip
        show_timeout_ip = args.show_timeout_ip
        show_unknow_ip = args.show_unknow_ip
        enable_match_result = args.enable_match_result
        enable_ignore_result = args.enable_ignore_result
        show_output = args.show_output
        username = args.username
        password = args.password
        save_file = args.save
        result_exp = args.result_exp
        save_match = args.save_match
        save_ignore = args.save_ignore

        last_match_ip_list,last_ignore_ip_list,all_ssh_result,all_bingo_result,all_nobingo_result = execute_ssh(csv_file_data,username,password,thread_num,str_match,re_match,command)
        
        if result_exp:
            all_ssh_result,all_bingo_result,all_nobingo_result = result_preprocess(all_ssh_result,all_bingo_result,all_nobingo_result,result_exp)


        if save_file:
            if save_match:
                save_result_to_file(save_file,all_bingo_result)
            elif save_ignore:
                save_result_to_file(save_file,all_nobingo_result)
            else:
                save_result_to_file(save_file,all_ssh_result)

        print('Using Time %.2fs' % (time.time() - start_time))
    elif sys.argv[1] == 'run_script':
        parser = argparse.ArgumentParser(description='run_script')
        parser.add_argument('run_script')
        parser.add_argument('--thread', dest='thread',default=1,type=int, help='thread num for execute ssh')
        parser.add_argument('--csv_file', dest='csv_file',default='',type=str, help='csv data')
        parser.add_argument('--ip', dest='ip',default='',type=str, help='ip')
        parser.add_argument('--username', dest='username',default='ubuntu',type=str, help='username')
        parser.add_argument('--password', dest='password',default='root',type=str, help='password')
        parser.add_argument('--match', dest='match',default='',type=str, help='match ssh result')
        parser.add_argument('--rematch', dest='rematch',default='',type=str, help='re-match ssh result')
        parser.add_argument('--show_auth_fail_ip', dest='show_auth_fail_ip',action='store_true',help='show auth fail ip')
        parser.add_argument('--show_match_ip', dest='show_match_ip',action='store_true',help='show all match ip list')
        parser.add_argument('--show_ignore_ip', dest='show_ignore_ip',action='store_true',help='show all ignore ip list')
        parser.add_argument('--show_timeout_ip', dest='show_timeout_ip',action='store_true',help='show timeout ip list')
        parser.add_argument('--show_unknow_ip', dest='show_unknow_ip',action='store_true',help='show unknow except ip list')
        parser.add_argument('--enable_match_result', dest='enable_match_result',action='store_true',help='show match ssh output result')
        parser.add_argument('--enable_ignore_result', dest='enable_ignore_result',action='store_true',help='show ignore ssh output result')
        parser.add_argument('-v', dest='show_output',action='store_true', help='no show ssh output')
        parser.add_argument('--save', dest='save',default='',type=str, help='save ssh result to file')
        parser.add_argument('--save_match', dest='save_match',action='store_true',help='save match result')
        parser.add_argument('--save_ignore', dest='save_ignore',action='store_true',help='save ignore result')
        parser.add_argument('--result_exp', dest='result_exp',default='',type=str, help='result process express')
        parser.add_argument('commandscript', help='SSH Execute Command Script')
        
        args = parser.parse_args()
        commandscript = args.commandscript
        str_match = args.match
        re_match = args.rematch
        thread_num = args.thread
        show_match_ip = args.show_match_ip
        show_ignore_ip = args.show_ignore_ip
        show_auth_fail_ip = args.show_auth_fail_ip
        enable_match_result = args.enable_match_result
        enable_ignore_result = args.enable_ignore_result
        show_output = args.show_output
        username = args.username
        password = args.password
        show_timeout_ip = args.show_timeout_ip
        show_unknow_ip = args.show_unknow_ip
        cvs_file = args.csv_file
        save_file = args.save
        result_exp = args.result_exp
        save_match = args.save_match
        save_ignore = args.save_ignore

        if cvs_file:
            csv_file_data = csv_loader.factory(cvs_file,False)
        else:
            ip = args.ip

            if ip:
                if os.path.exists(ip):
                    ip_file = open(ip)
                    data_list = ip_file.readlines()
                    ip_file.close()
                    ip_list = []

                    for ip_record in data_list:
                        ipdata = ip_record.strip()

                        if not ipdata:
                            continue

                        ip_list.append({
                            'ip': ipdata
                        })

                    csv_file_data = csv_loader.factory_with_new(ip_list)
                else:
                    csv_file_data = csv_loader.factory_with_new([{
                        'ip': ip,
                    }])
            else:
                print('No IP Data in --csv_file and --ip')
                exit()

        file = open(commandscript)
        command_list = file.readlines()
        file.close()

        last_match_ip_list = []
        last_ignore_ip_list = []
        all_ssh_result = {}
        all_bingo_result = {}
        all_nobingo_result = {}

        for command in command_list:
            command = command.strip()

            ignore_flag = 'ignore:'
            match_flag = 'match:'

            if command.startswith(ignore_flag):
                print(' Execute Ignore',len(last_ignore_ip_list))
                command = command[len(ignore_flag):]
                csv_data = csv_file_data.filter_by_data(last_ignore_ip_list)
            elif command.startswith(match_flag):
                print(' Execute Match',len(last_match_ip_list))
                command = command[len(match_flag):]
                csv_data = csv_file_data.filter_by_data(last_match_ip_list)
            else:
                print(' Execute All',csv_file_data.get_size())
                csv_data = csv_file_data

            last_match_ip_list,last_ignore_ip_list,all_ssh_result,all_bingo_result,all_nobingo_result = execute_ssh(csv_data,username,password,thread_num,str_match,re_match,command)

        if result_exp:
            all_ssh_result,all_bingo_result,all_nobingo_result = result_preprocess(all_ssh_result,all_bingo_result,all_nobingo_result,result_exp)

        if save_file:
            if save_match:
                save_result_to_file(save_file,all_bingo_result)
            elif save_ignore:
                save_result_to_file(save_file,all_nobingo_result)
            else:
                save_result_to_file(save_file,all_ssh_result)


    print('Using Time %.2fs' % (time.time() - start_time))
