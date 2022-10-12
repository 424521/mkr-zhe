#!/usr/bin/python

import os
import os.path
import sys
import json
from schema import Schema
from serializers import code_serializer
# (base, code_serializer, db_serializer, example_serializer, json_serializer)

def get_schma(schema_file):
 _file = open(schema_file)
 try:
  schema_text = _file.read( )
 finally:
  _file.close( )
 schema_text = Schema(json.loads(schema_text))
 return schema_text

def get_output(output):
 file = os.path.split(output)
 output = file[0]
 file_name = file[1]
 return output, file_name

def generate_core_code(schema_text, func_prefix, output_path, file_name):
 s = code_serializer.Serializer(func_prefix = func_prefix, output_path = output_path, file_name = file_name)
 s.serializer(schema_text)
 
def refresh_all_schema(schema_path, output_path):
 for name in os.listdir(schema_path): 
  path = os.path.join(schema_path, name)
  if os.path.isdir(path):
   continue
  
  try:
   schema_text = get_schma(path)
  except Exception as err:
   print(name +"schema transfer failed!!!!")
   continue
  
  core_name = name.split('.')
  generate_core_code(schema_text, func_prefix, output_path, core_name[0])
 
def parse_cmd_args():
 import argparse
 parser = argparse.ArgumentParser()

 parser.add_argument('-i', dest='schema', action='store', default=None,
        help='json schema file')

 parser.add_argument('-o', dest='output', action='store', default=None,
        help='save output of serializer file')

 args = parser.parse_args()
 if not (args.schema or args.output):
  parser.print_help()
  sys.exit(0)

 return args

def main():
 args = parse_cmd_args()
 print(args)
 if args.output:
    output = args.output
 output_path, file_name = get_output(output)
 print(output,output_path,file_name)
 
 #refresh_all_schema(args.schema, output_path)
  
 schema_text = get_schma(args.schema)
 print(schema_text)
 if args.output:
  s = code_serializer.Serializer(func_prefix = func_prefix, output_path = output_path, file_name = file_name)
  s.serializer(schema_text)

if __name__ == '__main__':
 main()