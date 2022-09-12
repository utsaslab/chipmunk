#!/usr/bin/env python3 

#To run : python3 cmAdapter.py -b code/tests/generic_039/base_test.cpp  -t code/tests/generic_039/generic_039 -p code/tests/generic_039
import os
import re
import sys
import stat
import subprocess
import argparse
import time
import itertools
from shutil import copyfile


#All functions that has options go here
FallocOptions = ['FALLOC_FL_ZERO_RANGE','FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE','FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE', '0',  'FALLOC_FL_KEEP_SIZE']

FsyncOptions = ['fsync','fdatasync']

RemoveOptions = ['remove','unlink']

LinkOptions = ['link','symlink']

WriteOptions = ['WriteData','WriteDataMmap', 'pwrite']

redeclare_map = {}

def build_parser():
    parser = argparse.ArgumentParser(description='Workload generator for concurrent testing')

    # global args
    parser.add_argument('--base_file', '-b', default='', help='Base test file to generate workload')
    parser.add_argument('--test_file', '-t', default='', help='J lang test skeleton to generate workload')

    # crash monkey args
    parser.add_argument('--target_path', '-p', default='../code/tests/', help='Directory to save the generated test files')

    parser.add_argument('--output_name', '-o', default='file', help='Name of the generated file')
    return parser

def print_setup(parsed_args):
    print('\n{: ^50s}'.format('Concurrent workload generator\n'))
    print('='*20, 'Setup' , '='*20, '\n')
    print('{0:20}  {1}'.format('Base test file', parsed_args.base_file))
    print('{0:20}  {1}'.format('Test skeleton', parsed_args.test_file))
    print('{0:20}  {1}'.format('Target directory', parsed_args.target_path))
    print('{0:20}  {1}'.format('Output file', parsed_args.output_name))
    print('\n', '='*48, '\n')

def create_dir(dir_path):
    try: 
        os.makedirs(dir_path)
    except OSError:
        if not os.path.isdir(dir_path):
            raise

def create_dict():
    operation_map = {'fsync': 0, 'fallocate': 0, 'open': 0, 'remove': 0}
    return operation_map

#These maps keep track of the line number in each method, to add the next function to in the C++ file
def updateThreadMap(index_map, num):
    index_map['thread'] += num
    index_map['setup'] += num
    index_map['run'] += num
    index_map['check'] += num
    index_map['define'] += num 

def updateSetupMap(index_map, num):
    index_map['setup'] += num
    index_map['run'] += num
    index_map['check'] += num
    index_map['define'] += num

def updateRunMap(index_map, num):
    index_map['run'] += num
    index_map['check'] += num
    index_map['define'] += num

def updateCheckMap(index_map, num):
    index_map['check'] += num
    index_map['define'] += num

def updateDefineMap(index_map, num):
    index_map['define'] += num

def insertDeclare(line, file, index_map):
    
    with open(file, 'r+') as declare:
        contents = declare.readlines()

        updateRunMap(index_map, 1)
        line = line.rstrip()
        
        to_insert = '\t\t\t\tint ' + line + ' = 0 ;\n'
        contents.insert(index_map['run'], to_insert)

        declare.seek(0)
        declare.writelines(contents)
        declare.close()


# Add the 'line' which declares a file/dir used in the workload into the 'file'
# at position specified in the 'index_map'
def insertDefine(line, file, index_map):
    with open(file, 'r+') as define:
        
        contents = define.readlines()
        line = line.rstrip()

        # initialize paths in the thread function
        updateThreadMap(index_map, 1)
        file_str = ''
        if len(line.split('/')) != 1 :
            for i in range(0, len(line.split('/'))):
                file_str += line.split('/')[i]
        else:
            file_str = line.split('/')[-1]
        file_str = file_str.rstrip()
        if file_str == 'test':
            to_insert = '\tstring ' + file_str + '_path = mnt_dir_; \n' 
        else:
            to_insert = '\tstring ' + file_str + '_path = mnt_dir_' + ' + "/' + line + '";\n'
        contents.insert(index_map['thread'], to_insert)
        
        #Initialize paths in setup phase
        updateSetupMap(index_map, 1)
        file_str = ''
        if len(line.split('/')) != 1 :
            for i in range(0, len(line.split('/'))):
                file_str += line.split('/')[i]
        else:
            file_str = line.split('/')[-1]
        file_str = file_str.rstrip()

        if file_str == 'test':
            to_insert = '\t\t\t\t' + file_str + '_path = mnt_dir_ ;\n'
        else:
            to_insert = '\t\t\t\t' + file_str + '_path = mnt_dir_' + ' + "/' + line + '";\n'
        
        contents.insert(index_map['setup'], to_insert)
        
        #Initialize paths in run phase
        updateRunMap(index_map, 1)
        file_str = ''
        if len(line.split('/')) != 1 :
            for i in range(0, len(line.split('/'))):
                file_str += line.split('/')[i]
        else:
            file_str = line.split('/')[-1]
        file_str = file_str.rstrip()

        if file_str == 'test':
            to_insert = '\t\t\t\t' + file_str + '_path = mnt_dir_ ;\n'
        else:
            to_insert = '\t\t\t\t' + file_str + '_path =  mnt_dir_' + ' + "/' + line + '";\n'
        contents.insert(index_map['run'], to_insert)
        
        #Initialize paths in check phase
        updateCheckMap(index_map, 1)
        file_str = ''
        if len(line.split('/')) != 1 :
            for i in range(0, len(line.split('/'))):
                file_str += line.split('/')[i]
        else:
            file_str = line.split('/')[-1]
        file_str = file_str.rstrip()

        if file_str == 'test':
            to_insert = '\t\t\t\t' + file_str + '_path = mnt_dir_ ;\n'
        else:
            to_insert = '\t\t\t\t' + file_str + '_path =  mnt_dir_' + ' + "/' + line + '";\n'
        contents.insert(index_map['check'], to_insert)
        
        #Update defines portion
        #Get only the file name. We don't want the path here
        updateDefineMap(index_map, 1)
        file_str = ''
        if len(line.split('/')) != 1 :
            for i in range(0, len(line.split('/'))):
                file_str += line.split('/')[i]
        else:
            file_str = line.split('/')[-1]
        file_str = file_str.rstrip()

        to_insert = '\t\t\t string ' + file_str + '_path; \n'

        contents.insert(index_map['define'], to_insert)
        
        define.seek(0)
        define.writelines(contents)
        define.close()

def initRunThread(new_file, index_map):
    with open(new_file, 'r+') as f:
        contents = f.readlines()

        # set up variables in the run_threads function
        to_insert = "\tstruct t_args *args = (struct t_args*)varg;\n\tfs_testing::user_tools::api::CmFsOps *cm_ = args->cm_;\n\tstring mnt_dir_(args->mnt_dir_);\n"
        contents.insert(index_map['thread'], to_insert)
        updateThreadMap(index_map, 2)

        f.seek(0)
        f.writelines(contents)

def initThreads(new_file, index_map):
    with open(new_file, 'r+') as f:
        contents = f.readlines()

        updateRunMap(index_map, 1)
        to_insert = "\t\t\t\tvoid* ret;\n\t\t\t\tint retval = 0;\n\t\t\t\tstruct t_args args;\n\t\t\t\targs.cm_ = cm_;\n\t\t\t\targs.mnt_dir_ = mnt_dir_;\n\t\t\t\tvector<pthread_t> pvec;\n\t\t\t\tfor (int i = 0; i < test_threads; i++) {\n\t\t\t\t\tpthread_t tid;\n\t\t\t\t\tpthread_create(&tid, NULL, run_thread, &args);\n\t\t\t\t\tpvec.push_back(tid);\n\t\t\t\t}\n"
        contents.insert(index_map['run'], to_insert)
        
        updateRunMap(index_map, 1)
        to_insert = "\t\t\t\tfor (int i = 0; i < test_threads; i++) {\n\t\t\t\t\tpthread_join(pvec[i], &ret);\n\t\t\t\t\tif ((intptr_t)ret != 0) {\n\t\t\t\t\t\tretval = (intptr_t)ret;\n\t\t\t\t\t}\n\t\t\t\t}\n"
        contents.insert(index_map['run'], to_insert)

        f.seek(0)
        f.writelines(contents)

def insertMark(contents, line, index_map, method):
    to_insert = '\n\tif ( cm_->CmMark('') < 0){\n\t\treturn &fail;\n\t}\n\n'

    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 4)

def insertOpenFile(contents, line, index_map, method):
    name = 'fd_' + line.split(' ')[1]
    decl = ' '
    if name not in redeclare_map:
        decl = 'int '
        redeclare_map[name] = 1
    
    # TODO: prevent redeclations here
    to_insert = '\n\t' + decl + 'fd_' + line.split(' ')[1] + ' = cm_->CmOpen(' + line.split(' ')[1] + '_path.c_str() , ' + line.split(' ')[2] + ' , ' + line.split(' ')[3] + '); \n\tif ( fd_' + line.split(' ')[1] + ' < 0 ) { \n\t\tif(errno != ENOENT) {\n\t\t\treturn &fail;\n\t\t} else {\n\t\t\treturn NULL;\n\t\t}\n\t}\n\n'
    
    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 9)

def insertCheckpoint(contents, line, index_map, method):
    to_insert = '\n\tif ( cm_->CmCheckpoint() < 0){ \n\t\treturn &fail;\n\t}\n//\tlocal_checkpoint += 1; \n//\tif (local_checkpoint == checkpoint) { \n//\t\treturn '+ line.split(' ')[1] + ';\n//\t}\n\n'
    
    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 8)

def insertClose(contents, line, index_map, method):
    to_insert = '\n\tif ( cm_->CmClose ( fd_' + line.split(' ')[1] + ') < 0){ \n\t\treturn &fail;\n\t}\n\n'
    
    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 4)

def insertMkdir(contents, line, index_map, method):
    to_insert = '\n\tif ( cm_->CmMkdir(' + line.split(' ')[1] + '_path.c_str() , ' + line.split(' ')[2] + ') < 0){ \n\t\tif (errno != EEXIST) {\n\t\t\t return &fail;\n\t\t}\n\t}\n\n'

    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 5)

def insertWrite(contents, option, line, index_map, method):
    if option == "write":
        to_insert = '\n\tif ( cm_->CmWriteData ( fd_' + line.split(' ')[1] + ', ' + line.split(' ')[2] + ', ' + line.split(' ')[3] + ') < 0){ \n\t\tcm_->CmClose( fd_' + line.split(' ')[1] + '); \n\t\treturn &fail;\n\t}\n\n'

        contents.insert(index_map['thread'], to_insert)
        updateThreadMap(index_map, 5)  
    elif option == "dwrite":
        name = 'offset_' + line.split(' ')[1]
        decl = ' '
        data_decl = ' '
        text_decl = ' '
        
        if name not in redeclare_map:
            decl = 'int '
            data_decl = 'void* data_' +line.split(' ')[1] + ';'
            text_decl = 'const char *text_' + line.split(' ')[1] +'  = \"ddddddddddklmnopqrstuvwxyz123456\";'
            redeclare_map[name] = 1

        to_insert ='\n\tcm_->CmClose(fd_' + line.split(' ')[1] + '); \n\tfd_' + line.split(' ')[1] + ' = cm_->CmOpen(' + line.split(' ')[1] +'_path.c_str() , O_RDWR|O_DIRECT|O_SYNC , 0777); \n\tif ( fd_' + line.split(' ')[1] +' < 0 ) { \n\t\tcm_->CmClose( fd_' + line.split(' ')[1] +'); \n\t\treturn &fail;\n\t}\n\n\t' + data_decl+'\n\tif (posix_memalign(&data_' + line.split(' ')[1] +' , 4096, ' + line.split(' ')[3] +' ) < 0) {\n\t\treturn &fail;\n\t}\n\n\t \n\t' +decl+ 'offset_'+ line.split(' ')[1] +' = 0;\n\t' + decl +'to_write_'+line.split(' ')[1] +' = ' + line.split(' ')[3] + ' ;\n\t'+ text_decl+ '\n\twhile (offset_'+line.split(' ')[1]+' < '+ line.split(' ')[3] +'){\n\t\tif (to_write_'+ line.split(' ')[1] +' < 32){\n\t\t\tmemcpy((char *)data_'+ line.split(' ')[1]+ '+ offset_'+ line.split(' ')[1] +', text_'+ line.split(' ')[1] +', to_write_' +line.split(' ')[1]+');\n\t\t\toffset_'+ line.split(' ')[1]+' += to_write_'+ line.split(' ')[1] +';\n\t\t}\n\t\telse {\n\t\t\tmemcpy((char *)data_'+ line.split(' ')[1] +'+ offset_'+line.split(' ')[1] +',text_'+line.split(' ')[1] +', 32);\n\t\t\toffset_'+line.split(' ')[1] +' += 32; \n\t\t} \n\t} \n\n\tif ( cm_->CmPwrite ( fd_' + line.split(' ')[1] + ', data_'+ line.split(' ')[1] + ', '  + line.split(' ')[3] + ', ' + line.split(' ')[2] +') < 0){\n\t\tcm_->CmClose( fd_' + line.split(' ')[1] + '); \n\t\treturn &fail;\n\t} \
        \n\tif ( cm_->CmFsync( fd_' + line.split(' ')[1] + ') < 0){ \n\t\treturn &fail;\n\t}\n\tcm_->CmClose(fd_' + line.split(' ')[1] + ');\n\n'

        contents.insert(index_map['thread'], to_insert)
        updateThreadMap(index_map, 35)


def insertFalloc(contents, line, index_map, method):
    to_insert = '\n\tif ( cm_->CmFallocate( fd_' + line.split(' ')[1] + ' , ' + line.split(' ')[2] + ' , ' + line.split(' ')[3] + ' , '  + line.split(' ')[4] + ') < 0){ \n\t\tcm_->CmClose( fd_' + line.split(' ')[1]  +');\n\t\t return &fail;\n\t}\n\n'

    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 5)  

def insertLink(contents, line, index_map, method):
    to_insert = '\n\tif ( cm_->CmLink (' + line.split(' ')[1] + '_path.c_str() , '+ line.split(' ')[2] + '_path.c_str() '+ ') < 0){ \n\t\tif (errno != EEXIST) {\n\t\t\treturn &fail;\n\t\t}\n\t}\n\n'

    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 5)

def insertRemoveFile(contents, option, line, index_map, method):
    if option == "remove":
        to_insert = '\n\tif ( '+ 'cm_->CmRemove' +'(' + line.split(' ')[1] + '_path.c_str() ) < 0){ \n\t\tif (errno != ENOENT) {\n\t\t\treturn &fail;\n\t\t}\n\t}\n\n'
    else:
        to_insert = '\n\tif ( '+ 'cm_->CmUnlink' +'(' + line.split(' ')[1] + '_path.c_str() ) < 0){ \n\t\tif (errno != ENOENT) {\n\t\t\treturn &fail;\n\t\t}\n\t}\n\n'

    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 5)

def insertRename(contents, line, index_map, method):
    to_insert = '\n\tif ( cm_->CmRename (' + line.split(' ')[1] + '_path.c_str() , '+ line.split(' ')[2] + '_path.c_str() '+ ') < 0){ \n\t\tif (errno != ENOENT) {\n\t\t\treturn &fail;\n\t\t}\n\t}\n\n'
    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 5)

def insertOpenDir(contents, line, index_map, method):
    name = 'fd_' + line.split(' ')[1]
    decl = ' '
    if name not in redeclare_map:
        decl = 'int '
        redeclare_map[name] = 1

    to_insert = '\n\t' + decl + 'fd_' + line.split(' ')[1] + ' = cm_->CmOpen(' + line.split(' ')[1] + '_path.c_str() , O_DIRECTORY , ' + line.split(' ')[2] + '); \n\tif ( fd_' + line.split(' ')[1] + ' < 0 ) {  \n\t\tif(errno != ENOENT) {\n\t\t\treturn &fail;\n\t\t} else {\n\t\t\treturn NULL;\n\t\t}\n\t}\n\n'

    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 9)

def insertTruncateFile(contents, line, index_map, method):
    to_insert = '\n\tif ( cm_->CmTruncate (' + line.split(' ')[1] + '_path.c_str(), ' + line.split(' ')[2] + ') < 0){ \n\t\treturn &fail;\n\t}\n\n'

    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 4)

def insertSymlink(contents, line, index_map, method): 
    to_insert = '\n\tif ( cm_->CmSymlink (' + line.split(' ')[1] + '_path.c_str() , '+ line.split(' ')[2] + '_path.c_str() '+ ') < 0){ \n\t\tif (errno != EEXIST) {\n\t\t\treturn &fail;\n\t\t}\n\t}\n\n'

    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 5)

def insertRmdir(contents, line, index_map, method):
    to_insert = '\n\tif ( ' + 'cm_->CmRmdir' + '(' + line.split(' ')[1] + '_path.c_str()) < 0){ \n\t\tif (errno != ENOENT) {\n\t\t\treturn &fail;\n\t\t}\n\t}\n\n'

    contents.insert(index_map['thread'], to_insert)
    updateThreadMap(index_map, 5)

def insertFunctions(line, file, index_map, method):
    with open(file, 'r+') as insert:
        contents = insert.readlines()

        if line.split(' ')[0] == "mark":
            updateThreadMap(index_map, 1)
            insertMark(contents, line, index_map, method)

        elif line.split(' ')[0] == "open":
            updateThreadMap(index_map, 1)
            insertOpenFile(contents, line, index_map, method)

        elif line.split(' ')[0] == "checkpoint": 
            updateThreadMap(index_map, 1)
            insertCheckpoint(contents, line, index_map, method)

        elif line.split(' ')[0] == "close":
            updateThreadMap(index_map, 1)
            insertClose(contents, line, index_map, method)

        elif line.split(' ')[0] == "mkdir":
            updateThreadMap(index_map, 1)
            insertMkdir(contents, line, index_map, method)

        elif line.split(' ')[0] == "write" or line.split(' ')[0] == "dwrite":
            updateThreadMap(index_map, 1)
            option = line.split(' ')[0]
            insertWrite(contents, option, line, index_map, method)

        elif line.split(' ')[0] == "falloc":
            updateThreadMap(index_map, 1)
            insertFalloc(contents, line, index_map, method)
        
        elif line.split(' ')[0] == "link":
            updateThreadMap(index_map, 1)
            insertLink(contents, line, index_map, method)

        elif line.split(' ')[0] == "unlink" or line.split(' ')[0] == "remove":
            updateThreadMap(index_map, 1)
            option = line.split(' ')[0]
            insertRemoveFile(contents, option, line, index_map, method)

        elif line.split(' ')[0] == "rename":
            updateThreadMap(index_map, 1)
            insertRename(contents, line, index_map, method)

        elif line.split(' ')[0] == "opendir":
            updateThreadMap(index_map, 1)
            insertOpenDir(contents, line, index_map, method)

        elif line.split(' ')[0] == "truncate":
            updateThreadMap(index_map, 1)
            insertTruncateFile(contents, line, index_map, method)

        elif line.split(' ')[0] == "symlink":
            updateThreadMap(index_map, 1)
            insertSymlink(contents, line, index_map, method)

        elif line.split(' ')[0] == "rmdir":
            updateThreadMap(index_map, 1)
            insertRmdir(contents, line, index_map, method)

        elif line.split(' ')[0] == "none":
            pass

        else:
            print("Unrecognized line", line)

        insert.seek(0)
        insert.writelines(contents)
    



def main():

    parsed_args = build_parser().parse_args()

    # print the test setup
    # print_setup(parsed_args)

    #check if test file exists
    if not os.path.exists(parsed_args.test_file) or not os.path.isfile(parsed_args.test_file):
        print(parsed_args.test_file + ' : No such test file\n')
        exit(1)

    #Create the target directory
    create_dir(parsed_args.target_path)

    #Create a pre-populated dictionary of replacable operations
    operation_map = create_dict()

    #Copy base file to target path
    base_test = parsed_args.base_file
    base_file = os.path.join(parsed_args.target_path,base_test.split('/')[-1])

    test_file = parsed_args.test_file

    index_map = {'thread': 0, 'define': 0, 'setup': 0, 'run': 0, 'check': 0}

    #iterate through the base file and populate these values
    index = 0
    with open(base_file, 'r') as f:
        contents = f.readlines()
        for index, line in enumerate(contents):
            index += 1
            line = line.strip()
            if line.find('setup') != -1:
                if line.split(' ')[2] == 'setup()':
                    index_map['setup'] = index
            elif line.find('run_thread') != -1:
                if line.split(' ')[1] == 'run_thread(void*':
                    index_map['thread'] = index
            elif line.find('run') != -1:
                if line.split(' ')[2] == 'run(':
                    index_map['run'] = index
            elif line.find('check_test') != -1:
                if line.split(' ')[2] == 'check_test(':
                    index_map['check'] = index
            elif line.find('private') != -1:
                if line.split(' ')[0] == 'private:':
                    index_map['define'] = index
            
    f.close()

    new_file = parsed_args.test_file + ".cpp"
    new_file = os.path.join(parsed_args.target_path, new_file)
    copyfile(base_file, new_file)
    method = ""
    new_index_map = index_map.copy()

    # initialize thread specific structures
    initRunThread(new_file, new_index_map)

    with open(test_file, 'r') as f:
        for line in f:
            # ignore newlines
            if line.split(' ')[0] == '\n':
                continue

            # lines beginning with # indicate which region of the base file to populate
            if line.split(' ')[0] == '#':
                method = line.strip().split()[-1]
                if (method != "setup"):
                    continue

            line = line.rstrip()

            if method == 'define':
                insertDefine(line, new_file, new_index_map)
            elif method == 'declare':
                insertDeclare(line, new_file, new_index_map)
            # here we're going to use setup as a signal to indicate that 
            # we can now add the pthread stuff to the main run function.
            # this may not be compatible with arbitrary j-lang files
            elif method == 'setup':
                initThreads(new_file, new_index_map)
            elif method == 'run':
                insertFunctions(line, new_file, new_index_map, method)
            

if __name__ == '__main__':
    main()
