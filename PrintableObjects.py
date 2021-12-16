import json

from volatility.renderers.basic import Address

class ModuleObject(object):
    def __init__(self, task, digest, algorithm, mod_base, mod_end, mod_name, section, create_time,
                 file_version, product_version, path, num_pages, num_valid_pages, print_time, offset, size, pe_memory_time, pre_processing_time, physical_addresses, preprocess, warnings, digesting_time, valid_pages):
        self.digest = digest
        self.process = self.get_filename(task)
        self.algorithm = algorithm
        self.pid = task.UniqueProcessId
        self.ppid = task.InheritedFromUniqueProcessId
        self.mod_base = mod_base
        self.mod_end = mod_end
        self.mod_name = mod_name
        self.Wow64 = task.IsWow64
        self.section = section
        self.sec_off = offset
        self.sec_size = size
        self.create_time = create_time
        self.file_version = file_version
        self.product_version = product_version
        self.path = path
        self.num_pages = num_pages
        self.num_valid_pages = num_valid_pages
        self.print_time = print_time
        self.pe_memory_time = pe_memory_time
        self.pre_processing_time = pre_processing_time
        self.physical_addresses=physical_addresses
        self.preprocess = preprocess
        self.warnings = warnings
        self.digesting_time = digesting_time
        self.valid_pages = valid_pages

    def get_generator(self):
        if self.print_time:
            return [
                str(self.process),
                int(self.pid),
                int(self.ppid),
                str(self.create_time),
                Address(self.mod_base),
                Address(self.mod_end),
                str(self.mod_name),
                int(self.Wow64),
                str(self.file_version),
                str(self.product_version),
                str(self.section),
                Address(self.sec_off),
                Address(self.sec_size),
                str(self.algorithm),
                self.preprocess,
                str(self.digest),
                str(self.path),
                str(self.num_pages),
                str(self.num_valid_pages),
                str(self.digesting_time),
                str(self.sec_size),
                str(self.pe_memory_time),
                str(self.pre_processing_time),
                str([hex(page).rstrip("L") if page else '*' for page in self.valid_pages])
            ]
        else:
            return [
                        str(self.process),
                        int(self.pid),
                        int(self.ppid),
                        str(self.create_time),
                        Address(self.mod_base),
                        Address(self.mod_end),
                        str(self.mod_name),
                        int(self.Wow64),
                        str(self.file_version),
                        str(self.product_version),
                        str(self.section),
                        Address(self.sec_off),
                        Address(self.sec_size),
                        str(self.algorithm),
                        self.preprocess,
                        str(self.digest),
                        str(self.path),
                        str(self.num_pages),
                        str(self.num_valid_pages),
                        str([hex(page).rstrip("L") if page else '*' for page in self.valid_pages])
                    ]

    def get_unified_output(self):
        if self.print_time:
            return [
                ('Process', '25'),
                ('Pid', '4'),
                ('PPid', '4'),
                ('Create Time', '28'),
                ('Module Base', '[addr]'),
                ('Module End', '[addr]'),
                ('Module Name', '33'),
                ('Wow64', '6'),
                ('File Version', '14'),
                ('Product Version', '10'),
                ('Section', '18'),
                ('Section Offset', '[addr]'),
                ('Section Size', '[addr]'),
                ('Algorithm', '6'),
                ('Pre-process', '6'),
                ('Generated Hash', '100'),
                ('Path', '46'),
                ('Num Page', '4'),
                ('Num Valid Page', '4'),
                ('Computation Time', '30'),
                ('Size', '30'),
                ('PE Memory Computation Time', '30'),
                ('Pre-processing Time', '30'),
                ('Physical pages', '30'),

            ]
        else:
            return [
                        ('Process', '25'),
                        ('Pid', '4'),
                        ('PPid', '4'),
                        ('Create Time', '28'),
                        ('Module Base', '[addr]'),
                        ('Module End', '[addr]'),
                        ('Module Name', '33'),
                        ('Wow64', '6'),
                        ('File Version', '14'),
                        ('Product Version', '10'),
                        ('Section', '18'),
                        ('Section Offset', '[addr]'),
                        ('Section Size', '[addr]'),
                        ('Algorithm', '6'),
                        ('Pre-process', '6'),
                        ('Generated Hash', '100'),
                        ('Path', '46'),
                        ('Num Page', '4'),
                        ('Num Valid Page', '4'),
                        ('Physical pages', '30'),
                    ]

    def _json(self):
        return json.dumps(self._dict())

    def _dict(self):
        ret = {}

        ret['Process'] = str(self.process)
        ret['Pid'] = int(self.pid)
        ret['PPid'] = int(self.ppid)
        ret['Create Time'] = int(self.create_time)
        ret['Module Base'] = hex(self.mod_base)
        ret['Module End'] = hex(self.mod_end)
        ret['Module Name'] = str(self.mod_name)
        ret['Wow64'] = int(self.Wow64)
        ret['File Version'] = str(self.file_version)
        ret['Product Version'] = str(self.product_version)
        ret['Section'] = str(self.section)
        ret['Section Offset'] = hex(self.sec_off)
        ret['Section Size'] = int(self.sec_size)
        ret['Algorithm'] = str(self.algorithm)
        ret['Pre-process'] = str(self.preprocess)
        ret['Generated Hash'] = str(self.digest)
        ret['Path'] = str(self.path)
        ret['Num Page'] = str(self.num_pages)
        ret['Num Valid Pages'] = str(self.num_valid_pages)
        ret['Computation Time'] = str(self.digesting_time)
        ret['Size'] = str(self.sec_size)
        ret['PEMemory time'] = str(self.pe_memory_time)
        ret['Pre-processing Time'] = str(self.pre_processing_time)
        ret['Physical pages'] = str([hex(page).rstrip("L") if page else '*' for page in self.valid_pages])
        ret['warnings'] = str(self.warnings)
        return ret

    def get_filename(self, task):
        for mod in task.get_load_modules():
            return mod.BaseDllName


class CompareObject(ModuleObject):
    def __init__(self, task, digest, algorithm, mod_base, mod_end, mod_name, section, create_time,
                 file_version, product_version, path, num_pages, num_valid_pages, print_time, offset, size, pe_memory_time, pre_processing_time, physical_addresses, preprocess, warnings, digesting_time, valid_pages, compared_digest, compared_page, similarity, comparison_time):
        super(CompareObject, self).__init__(task, digest, algorithm, mod_base, mod_end, mod_name, section, create_time,
                 file_version, product_version, path, num_pages, num_valid_pages, print_time, offset, size, pe_memory_time, pre_processing_time, physical_addresses, preprocess, warnings, digesting_time, valid_pages)
        self.compared_digest = compared_digest
        self.similarity = similarity
        self.comparison_time = comparison_time
        self.compared_page = compared_page
    
    def get_generator(self):
        if self.print_time:
            return super(CompareObject, self).get_generator() + [
                        str(self.compared_digest),
                        str(self.compared_page),
                        str(self.similarity),
                        str(self.comparison_time)
                    ]
        else:
            return super(CompareObject, self).get_generator() + [
                str(self.compared_digest),
                str(self.compared_page),
                str(self.similarity)
            ]

    def get_unified_output(self):
        if self.print_time:
            return super(CompareObject, self).get_unified_output() + [
                        ('Compared Digest', '100'),
                        ('Compared Page', '14'),
                        ('Similarity', '9'),
                        ('Computation Time', '30')
                    ]
        else:
            return super(CompareObject, self).get_unified_output() + [
                ('Compared Digest', '100'),
                ('Compared Page', '14'),
                ('Similarity', '9')
            ]

    def _dict(self):
        ret = super(CompareObject, self)._dict()

        ret['Compared Digest'] = str(self.compared_digest)
        ret['Compared Page'] = str(self.compared_page)
        ret['Similarity'] = str(self.similarity)
        ret['Computation Time'] = str(self.comparison_time)

        return ret