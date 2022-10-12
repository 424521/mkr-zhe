import json

import sys


import base

from schema2struct.template import Template


sys.path.append("..")

from schema import Schema


header_template_file = 'sg_json_serializer.h'

src_template_file = 'sg_json_serializer.c'

data_wrap_template_file = 'sg_cfg_wrap.c'

header_wrap_template_file = 'sg_cfg_wrap.h'


class Serializer(base.Serializer, Template):

	def __init__(self, func_prefix = None, output_path=None, file_name=None):

		self.core_api = []

		super(Serializer, self).__init__(func_prefix, output_path, file_name)

		self.header_template = Template.load_template(header_template_file)

		self.src_template = Template.load_template(src_template_file)


	def core_api_append(self, api):

		self.core_api.append(api)


	def get_core_api(self):

		return self.core_api


	def _replace_header_template(self, old, value):

		self.header_template = self.header_template.replace(old, value)


	def _replace_src_template(self, old, value):

		self.src_template = self.src_template.replace(old, value)


	def _generate_struct(self):

		code = ''

		for key, struct_field in enumerate(self.get_struct_list()):

			if code != '':

				code += '};	\n\n'


			code += '%s {\n' %(struct_field.get_struct())

			for k, other_field in enumerate(struct_field.get_element()):

				code += '\t%s;\n' %(other_field.get_variable())


		code += '};\n'

		self._replace_header_template('$SG_STRUCT', code)


		#print self.header_template


	def _generate_j2s_data_copy(self, struct_field, tab, __json_obj, __struct):

		code = ''


		code += '\n'

		for key, field in enumerate(struct_field.get_element()):

			# when auto generate need continue

			if field.is_auto_created():

				continue


			array_elem = '&%s->%s' %(__struct, field.get_variable_name())

			struct_elem = '&%s->%s' %(__struct, field.get_variable_name())

			current_elem = '%s->%s' %(__struct, field.get_variable_name())


			if field.is_array():

				function = '__sg_%s_j2s' %(field.get_struct_name())

				code += '%sSG_JSON_CALL_FUNCTION(%s, %s, %s);\n' %(tab, function, __json_obj, array_elem)

			elif field.is_struct():

				function = '__sg_%s_j2s' %(field.get_struct_name())

				code += '%sSG_JSON_CALL_FUNCTION(%s, %s, %s);\n' %(tab, function, __json_obj, struct_elem)

			elif field.is_int():

				if field.is_ex():

					code += '%sSG_JSON_GET_INT_EX(%s, %s);\n' \

						%(tab, current_elem, __json_obj)

				else:

					code += '%sSG_JSON_GET_INT(%s, %s, \"%s\");\n' \

						%(tab, current_elem, __json_obj, field.get_mapped_name())

			elif field.is_long():

				if field.is_ex():

					code += '%sSG_JSON_GET_LONG_EX(%s, %s);\n' \

							% (tab, current_elem, __json_obj)

				else:

					code += '%sSG_JSON_GET_LONG(%s, %s, \"%s\");\n' \

							% (tab, current_elem, __json_obj, field.get_mapped_name())

			elif field.is_u64():

				if field.is_ex():

					code += '%sSG_JSON_GET_U64_EX(%s, %s);\n' \

						% (tab, current_elem, __json_obj)

				else:

					code += '%sSG_JSON_GET_U64(%s, %s, \"%s\");\n' \

							% (tab, current_elem, __json_obj, field.get_mapped_name())

			elif field.is_string():

				if field.is_ex():

					code += '%sSG_JSON_GET_STRING_EX(%s, %s);\n' \

						%(tab, current_elem, __json_obj)

				else:

					code += '%sSG_JSON_GET_STRING(%s, %s, \"%s\");\n' \

						%(tab, current_elem, __json_obj, field.get_mapped_name())

			elif field.is_pointer():

				code += '%s %s = %s;\n' \

					%(tab, current_elem, __json_obj)


		return code


	def _generate_j2s_function(self, struct_field):

		tab = ''

		struct = ''


		if struct_field.is_array():

			struct = '%s **__struct' %(struct_field.get_struct())

		elif struct_field.is_struct():

			struct = '%s *__struct' %(struct_field.get_struct())


		code = '''

static int __sg_%s_j2s(sg_json_obj *__json_obj, %s)

{

	int ret = SG_JSON_ERR;

	__maybe_unused int i, items;

	sg_json_obj *__current_obj = NULL;

	__maybe_unused sg_json_obj *__elem_obj = NULL;

		''' %(struct_field.get_struct_name(),

		   struct)


		if struct_field.is_array():

			code += '''

	%s *__current = NULL;

	%s *__header = NULL;

			''' %(struct_field.get_struct(),

				  struct_field.get_struct())


		code += '''

	__current_obj = sg_json_obj_get(__json_obj, \"%s\");

	if (sg_json_obj_error(__current_obj)) {

		// TODO: when json object is null

		ret = SG_JSON_OK;

		goto cleanup;

	}

 	''' %(struct_field.get_mapped_name())


		if struct_field.is_array():

			code += '''

	items = sg_json_obj_array_len(__current_obj);

	for (i = 0; i < items; ++i) {

		__current = sg_cfg_alloc(sizeof(%s));

		if (!__current) {

			goto cleanup;

		}


		SG_JSON_GET_ARRAY(__elem_obj, __current_obj, i);

			''' %(struct_field.get_struct())


		if struct_field.is_array():

			tab = '\t\t'

			__struct = '__current'

			__json_obj = '__elem_obj'

		else:

			tab = '\t'

			__struct = '__struct'

			__json_obj = '__current_obj'

		code += self._generate_j2s_data_copy(struct_field, tab, __json_obj, __struct)


		if struct_field.is_array():

			code += '''

		%s%s_add(&__header, __current);

	}


	ret = SG_JSON_OK;


cleanup:

	*__struct = __header;

	return ret;

}

''' %(self.func_prefix,

		struct_field.get_variable_name())

		else:

			code += '''

	ret = SG_JSON_OK;


cleanup:

	return ret;

}

'''

		return code


	def _generate_s2j_data_copy(self, struct_field, tab, __json_obj, __struct):

		code = ''


		code += '\n'

		for key, field in enumerate(struct_field.get_element()):

			# when auto generate need continue

			if field.is_auto_created():

				continue


			array_elem = '%s->%s' %(__struct, field.get_variable_name())

			struct_elem = '&%s->%s' %(__struct, field.get_variable_name())

			current_elem = '%s->%s' %(__struct, field.get_variable_name())


			if field.is_array():

				function = '__sg_%s_s2j' %(field.get_struct_name())

				code += '%sSG_JSON_CALL_FUNCTION(%s, &%s, %s);\n' %(tab, function, __json_obj, array_elem)

			elif field.is_struct():

				function = '__sg_%s_s2j' %(field.get_struct_name())

				code += '%sSG_JSON_CALL_FUNCTION(%s, &%s, %s);\n' %(tab, function, __json_obj, struct_elem)

			elif field.is_int():

				if field.is_ex():

					code += '%sSG_JSON_SET_INT_EX(%s, %s);\n' \

						%(tab, "__current_obj", current_elem)

				else:

					code += '%sSG_JSON_SET_INT(%s, \"%s\", %s);\n' \

						%(tab, __json_obj, field.get_mapped_name(), current_elem)

			elif field.is_long():

				if field.is_ex():

					code += '%sSG_JSON_SET_LONG_EX(%s, %s);\n' \

						%(tab, "__current_obj", current_elem)

				else:

					code += '%sSG_JSON_SET_LONG(%s, \"%s\", %s);\n' \

						%(tab, __json_obj, field.get_mapped_name(), current_elem)

			elif field.is_u64():

				if field.is_ex():

					code += '%sSG_JSON_SET_U64_EX(%s, %s);\n' \

						%(tab, "__current_obj", current_elem)

				else:

					code += '%sSG_JSON_SET_U64(%s, \"%s\", %s);\n' \

						%(tab, __json_obj, field.get_mapped_name(), current_elem)

			elif field.is_string():

				if field.is_ex():

					code += '%sSG_JSON_SET_STRING_EX(%s, %s);\n' \

						%(tab, "__current_obj", current_elem)

				else:

					code += '%sSG_JSON_SET_STRING(%s, \"%s\", %s);\n' \

						%(tab, __json_obj, field.get_mapped_name(), current_elem)


		if struct_field.is_array():

			code += '%s%s = %s->next;' %(tab, __struct, __struct)

		return code


	def _generate_s2j_common_function(self, struct_field):

		tab = ''

		__parent = ''

		__parent_obj = ''


		if struct_field.is_array():

			obj_new = 'sg_json_obj_new_array'

		else:

			obj_new = 'sg_json_obj_new'


		code = '''

static int __sg_%s_s2j(sg_json_obj **__json_obj, %s *__struct)

{

	int ret = SG_JSON_ERR;

	sg_json_obj *__current_obj = NULL;

	__maybe_unused sg_json_obj *__elem_obj = NULL;


	%s *__current = __struct;


	__current_obj = %s();

	if (sg_json_obj_error(__current_obj)) {

		goto cleanup;

	}

	
	if (*__json_obj) {

		sg_json_obj_add(*__json_obj, \"%s\", __current_obj);

	}

	
 	''' %(struct_field.get_variable_name(),

		struct_field.get_struct(),

		struct_field.get_struct(),

		obj_new,

		struct_field.get_mapped_name())


		if struct_field.is_array():

			if struct_field.is_ex():

				code += '''

	while (__current) {

				'''

			else:

				code += '''

	while (__current) {

		SG_JSON_SET_ARRAY(__current_obj, __elem_obj);

				'''


		if struct_field.is_array():

			tab = '\t\t'

			__struct = '__current'

			__json_obj = '__elem_obj'

		else:

			tab = '\t'

			__struct = '__current'

			__json_obj = '__current_obj'

		code += self._generate_s2j_data_copy(struct_field,

											 tab, __json_obj, __struct)


		if struct_field.is_array():

			code += '''

	}

			'''


		code += '''

	ret = SG_JSON_OK;


cleanup:

	if (!*__json_obj) {

		*__json_obj = __current_obj;

	}

	return ret;

}

'''

		return code


	def _generate_s2j_pointer_function(self, struct_field):

		_key = ''

		for key, field in enumerate(struct_field.get_element()):

			# when auto generate need continue

			if field.is_auto_created():

				continue


			_key_elem = '__struct->%s' %(field.get_variable_name())


		code = '''

static int __sg_%s_s2j(sg_json_obj **__json_obj, %s *__struct)

{

	sg_json_obj_add(*__json_obj, \"%s\", (sg_json_obj*)%s);

	return SG_JSON_OK;

}

 	''' %(struct_field.get_variable_name(),

		struct_field.get_struct(),

		struct_field.get_mapped_name(),

		_key_elem)

		return code


	def _generate_s2j_function(self, struct_field):

		if struct_field.is_pointer():

			return self._generate_s2j_pointer_function(struct_field)

		else:

			return self._generate_s2j_common_function(struct_field)


	def _generate_core_code(self):

		j2s = ''

		s2j = ''


		for key, struct_field in enumerate(self.get_struct_list()):

			j2s += self._generate_j2s_function(struct_field)

			s2j += self._generate_s2j_function(struct_field)


		self._replace_src_template('$SG_JS2_INTERNAL_FUNCTION', j2s)

		self._replace_src_template('$SG_S2J_INTERNAL_FUNCTION', s2j)


		#print self.src_template


	def _generate_j2s_api(self, struct_field):

		api = 'extern void *%s%s_j2s(void *__json_obj)' \

			  %(self.func_prefix,

		struct_field.get_variable_name())

		self.core_api_append(api)


		code = '''

void *%s%s_j2s(void *__json_obj)

{

	int ret = SG_JSON_ERR;

	__maybe_unused %s *__struct = NULL;

		'''  %(self.func_prefix,

			   struct_field.get_variable_name(),

			   struct_field.get_struct())


		if struct_field.is_array():

			code += '''

	ret = __sg_%s_j2s(__json_obj, &__struct);

	if (ret != SG_JSON_OK) {

		%s%s_free(__struct);

		__struct = NULL;

	}

		'''  %(struct_field.get_variable_name(),

			   self.func_prefix,

			   struct_field.get_variable_name())

		else:

			code += '''

	__struct = sg_cfg_alloc(sizeof(%s));

	if (!__struct) {

		return NULL;

	}


	ret = __sg_%s_j2s(__json_obj, __struct);

	if (ret != SG_JSON_OK) {

		%s%s_free(__struct);

		__struct = NULL;

	}

	''' % (struct_field.get_struct(),

		struct_field.get_variable_name(),

		self.func_prefix,

		struct_field.get_variable_name())


		code += '''

	return __struct;

}

'''

		return code


	def _generate_s2j_api(self, struct_field):

		api = 'extern void *%s%s_s2j(%s *__struct)' \

			  %(self.func_prefix,

				struct_field.get_variable_name(),

				struct_field.get_struct())

		self.core_api_append(api)


		code = '''

void *%s%s_s2j(%s *__struct)

{

	int ret = SG_JSON_ERR;

	sg_json_obj *__json_obj = NULL;


	__json_obj = sg_json_obj_new();

	if (sg_json_obj_error(__json_obj)) {

		return NULL;

	}

	
	ret = __sg_%s_s2j(&__json_obj, __struct);

	if (ret != SG_JSON_OK && __json_obj) {

		sg_json_obj_free(__json_obj);

		__json_obj = NULL;

	}


	return __json_obj;

}

''' %(self.func_prefix,

	  struct_field.get_variable_name(),

		struct_field.get_struct(),

		struct_field.get_variable_name())


		return code

		
	def _generate_s2j_ex_api(self, struct_field):

		api = 'extern void *%s%s_s2j_ex(%s *__struct)' \

			  %(self.func_prefix,

				struct_field.get_variable_name(),

				struct_field.get_struct())

		self.core_api_append(api)


		code = '''

void *%s%s_s2j_ex(%s *__struct)

{

	int ret = SG_JSON_ERR;

	sg_json_obj *__json_obj = NULL;

	
	ret = __sg_%s_s2j(&__json_obj, __struct);

	if (ret != SG_JSON_OK && __json_obj) {

		sg_json_obj_free(__json_obj);

		__json_obj = NULL;

	}

	
	return __json_obj;

}

''' %(self.func_prefix,

	  struct_field.get_variable_name(),

		struct_field.get_struct(),

		struct_field.get_variable_name())


		return code

		
	def _generate_s2j_write_api(self, struct_field):

		api = 'extern int %s%s_s2j_write(void *generator, %s *__struct)' \

			  %(self.func_prefix,

				struct_field.get_variable_name(),

				struct_field.get_struct())

		self.core_api_append(api)


		code = '''

int %s%s_s2j_write(void *generator, %s *__struct)

{

	int ret = SG_JSON_ERR;

	sg_json_obj *__json_obj = NULL;

	sg_json_obj *__write_obj = NULL;

	
	ret = __sg_%s_s2j(&__json_obj, __struct);

	if (ret != SG_JSON_OK || !__json_obj) {

		ret = SG_JSON_GENERATOR_UNACCPT_PARA;

		goto err;

	}

	
	__write_obj = __json_obj;

	if (sg_json_obj_get_type(__json_obj) == sg_json_type_array) {

		__write_obj = sg_json_obj_array_get_idx(__json_obj, 0);

	}

	
	if (sg_json_obj_error(__write_obj)) {

		ret = SG_JSON_GENERATOR_UNACCPT_PARA;

		goto err;	

	}

	
	ret = sg_json_generator_writeJsonString(generator,

		 sg_json_obj2string(__write_obj));

	
err:		 

	if (__json_obj) {

		sg_json_obj_free(__json_obj);	

	}

	return ret;

}

''' %(self.func_prefix,

	  struct_field.get_variable_name(),

		struct_field.get_struct(),

		struct_field.get_variable_name())


		return code

	
	def _generate_s2j_start_api(self, struct_field):

		api = 'extern void %s%s_s2j_start(void *generator)' \

			  %(self.func_prefix,

				struct_field.get_variable_name())

		self.core_api_append(api)


		code = '''

void %s%s_s2j_start(void *generator)

{

	sg_json_generator_writeArrayFieldStart(generator, \"%s\");

}

''' %(self.func_prefix,

	  struct_field.get_variable_name(),

		struct_field.get_variable_name())

		
		return code

	
	def _generate_s2j_end_api(self, struct_field):

		api = 'extern void %s%s_s2j_end(void *generator)' \

			  %(self.func_prefix,

				struct_field.get_variable_name())

		self.core_api_append(api)


		code = '''

void %s%s_s2j_end(void *generator)

{

	sg_json_generator_writeArrayFieldEnd(generator, \"%s\");

}

''' %(self.func_prefix,

	  struct_field.get_variable_name(),

		struct_field.get_variable_name())

		
		return code

	
	
	def _generate_free_internal(self, struct_field):

		code = ''


		code += '''

static void __sg_%s_free(%s *__struct, int current_free)

{

	__maybe_unused %s *q;

	__maybe_unused %s *p = __struct;

	__maybe_unused %s *__current = __struct;

''' %(struct_field.get_variable_name(),

		struct_field.get_struct(),

	  	struct_field.get_struct(),

	  	struct_field.get_struct(),

	  	struct_field.get_struct())


		if struct_field.is_array():

			code += '''

	while (p) {

		q = p;

		p = p->next;

		__current = q;

'''

		for key, field in enumerate(struct_field.get_element()):

			if field.is_auto_created():

				continue


			if field.is_struct():

				param = '&__current->%s' %(field.get_variable_name())

				tab = '\t'

			elif field.is_array():

				param = '__current->%s' %(field.get_variable_name())

				tab = '\t'


			if field.is_struct() or field.is_array():

				code += '''

	__sg_%s_free(%s, 0);

	 '''%(field.get_variable_name(),

		param)


		if struct_field.is_array():

			code += '''

		sg_cfg_free(q);

	}'''

		elif struct_field.is_struct():

			code += '''

	if (current_free) {

		sg_cfg_free(__struct);

	}'''

		code += '''

}

'''

		return code


	def _generate_free_external(self, struct_field):

		code = ''

		api = 'extern void %s%s_free(%s *__struct)' \

			  %(self.func_prefix,

				struct_field.get_variable_name(),

				struct_field.get_struct())

		self.core_api_append(api)


		code += '''

void %s%s_free(%s *__struct)

{

	__sg_%s_free(__struct, 1);

}

''' %(self.func_prefix,

	  struct_field.get_variable_name(),

		struct_field.get_struct(),

	  	struct_field.get_variable_name())

		return code


	def _generate_free_api(self, struct_field):

		code = ''

		code += self._generate_free_internal(struct_field)

		code += self._generate_free_external(struct_field)

		return code


	def _generate_alloc_api(self, struct_field):

		#if not struct_field.is_array():

		#	return ''


		api = 'extern void *%s%s_alloc(void)' \

			  %(self.func_prefix,

				struct_field.get_variable_name())

		self.core_api_append(api)


		code = '''

void *%s%s_alloc()

{

	return sg_cfg_alloc(sizeof(%s));

}

'''  %(self.func_prefix,

		struct_field.get_variable_name(),

		struct_field.get_struct())

		return code


	def _generate_add_api(self, struct_field):

		if not struct_field.is_array():

			return ''


		api = 'extern void %s%s_add(%s **__header, %s *__current)' \

			  %(self.func_prefix,

				struct_field.get_variable_name(),

				struct_field.get_struct(),

				struct_field.get_struct())

		self.core_api_append(api)


		code = '''

void %s%s_add(%s **__header, %s *__current)

{

	%s *p, *q;

	if (!*__header) {

		*__header = __current;

		return;

	}

	p = *__header;

	while (p) {

		q = p;

		p = p->next;

	}

	q->next = __current;

}

		''' %(self.func_prefix,

			  struct_field.get_variable_name(),

			  struct_field.get_struct(),

			  struct_field.get_struct(),

			  struct_field.get_struct())

		return code


	def _generate_get_api(self, struct_field):

		if not struct_field.is_array():

			return ''


		api = 'extern void *%s%s_get_next(%s *__struct)' \

			  %(self.func_prefix,

				struct_field.get_variable_name(),

				struct_field.get_struct())

		self.core_api_append(api)


		code = '''

void * %s%s_get_next(%s *__struct)

{

	return __struct ? __struct->next : NULL;

}

		''' %(self.func_prefix,

			  struct_field.get_variable_name(),

			  struct_field.get_struct())

		return code


	def _generate_get_size_api(self, struct_field):

		if not struct_field.is_array():

			return ''


		api = 'extern int %s%s_get_size(%s *__struct)' \

			  %(self.func_prefix,

				struct_field.get_variable_name(),

				struct_field.get_struct())

		self.core_api_append(api)


		code = '''

int %s%s_get_size(%s *__struct)

{

	int count = 0;

	%s *p = __struct;

	while (p) {

		count++;

		p = p->next;

	}

	return count;

}

		''' %(self.func_prefix,

			  struct_field.get_variable_name(),

			  struct_field.get_struct(),

			  struct_field.get_struct())

		return code


	def _generate_core_api(self):

		j2s = ''; s2j = ''; s2j_ex = '';

		s2j_write = ''; s2j_start = ''; s2j_end = '';

		alloc = ''; add = '';

		get = ''; size = '';

		free = ''; api = '';


		for key, struct_field in enumerate(self.get_struct_list()):

			j2s += self._generate_j2s_api(struct_field)

			s2j += self._generate_s2j_api(struct_field)

			s2j_ex += self._generate_s2j_ex_api(struct_field)

			s2j_write += self._generate_s2j_write_api(struct_field)

			s2j_start += self._generate_s2j_start_api(struct_field)

			s2j_end += self._generate_s2j_end_api(struct_field)

			alloc += self._generate_alloc_api(struct_field)

			add += self._generate_add_api(struct_field)

			get += self._generate_get_api(struct_field)

			size += self._generate_get_size_api(struct_field)

			free += self._generate_free_api(struct_field)


		for key, core_api in enumerate(self.get_core_api()):

			api += '%s;\n' %(core_api)


		self._replace_src_template('$SG_J2S_API', j2s)

		self._replace_src_template('$SG_S2J_API', s2j)

		self._replace_src_template('$SG_S2J_EX_API', s2j_ex)

		self._replace_src_template('$SG_S2J_WRITE_API', s2j_write)

		self._replace_src_template('$SG_S2J_START_API', s2j_start)

		self._replace_src_template('$SG_S2J_END_API', s2j_end)

		self._replace_src_template('$SG_ALLOC_API', alloc)

		self._replace_src_template('$SG_ADD_API', add)

		self._replace_src_template('$SG_GET_API', get)

		self._replace_src_template('$SG_SIZE_API', size)

		self._replace_src_template('$SG_FREE_API', free)

		self._replace_header_template('$SG_CORE_API', api)


	def _generate_other(self):

		header_file_def = '__SG_%s_H__' %(self.file_name.upper())

		self._replace_header_template('$SG_HEADER_DEF', header_file_def)


		file_name = '%s.h' %(self.file_name)

		self._replace_src_template('$SG_HEADER_FILE', file_name)


	def _generate_output_file(self):

		core_code = '%s/%s.c' %(self.output_path, self.file_name)

		self.save_file(core_code, self.src_template)


		core_api = '%s/%s.h' %(self.output_path, self.file_name)

		self.save_file(core_api, self.header_template)


		Template.copy_template(data_wrap_template_file, self.output_path)

		Template.copy_template(header_wrap_template_file, self.output_path)


	def serializer(self, schema_text=None):

		super(Serializer, self).serializer(schema_text)

		self._generate_struct()

		self._generate_core_code()

		self._generate_core_api()

		self._generate_other()

		self._generate_output_file()


if __name__ == '__main__':

	_file = open(sys.argv[1])

	try:

		schema_text = _file.read()

	finally:

		_file.close()


	schema_text = Schema(json.loads(schema_text))

	s = Serializer(sys.argv[2], sys.argv[3])

	s.serializer(schema_text)
