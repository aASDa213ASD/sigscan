import pymem
import pymem.memory
import pymem.ressources.kernel32
import pymem.ressources.structure
import regex as re


class Memory():
    bypass_protections = [
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READWRITE,
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READONLY,
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
    ]
    
    def scan_signature(self, handle: int, address: int, pattern: bytes):
        result = None
        mbi = pymem.memory.virtual_query(handle, address)
        next_region = mbi.BaseAddress + mbi.RegionSize

        if mbi.protect not in self.bypass_protections or \
        mbi.state != pymem.ressources.structure.MEMORY_STATE.MEM_COMMIT:
            return next_region, None

        bytes = pymem.memory.read_bytes(handle, address, mbi.RegionSize)
        match = re.search(pattern, bytes, re.DOTALL)
        if match:
            result = address + match.span()[0]
        
        return next_region, result
    
    def scan_handle(self, handle: int, module, pattern: bytes):
        self.base_addr = module.lpBaseOfDll
        self.max_addr = module.lpBaseOfDll + module.SizeOfImage
        self.region_addr = self.base_addr
        while self.region_addr < self.max_addr:
            self.region_addr, result = self.scan_signature(handle, self.region_addr, pattern)
            if result:
                break
        return result


class Offsetdater(Memory):
    def __init__(self, module: str):
        self.mem = pymem.Pymem(module)
        self.handle = self.mem.process_handle
        self.module = pymem.process.module_from_name(self.handle, module)
    
    def get_signature(self, pattern: bytes):
        test = self.scan_handle(self.handle, self.module, pattern)
        test_addr = self.mem.read_int(test + 1 + 1) - self.module.lpBaseOfDll
        return hex(test_addr)

    def read_signatures(self):
        with open('signatures.txt') as f:
            for signature in f:
                object_name, pattern = signature.split(',')
                pattern = pattern.replace(' ?', '.').replace(' ', '\\x')
                print(object_name, self.get_signature(bytes(pattern[:-1], 'ascii')))


if __name__ == '__main__':
    offsets = Offsetdater('League of Legends.exe')
    offsets.read_signatures()