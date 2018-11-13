class Context:
    def __init__(self):
        #self.variables = {} vars globais
        self.functions = {}
        self.vulnerabilities = []
        self.registry = {"RAX": "",
                        "RBX": "", "RCX": "", "RDX": "", "RDI": "",
                        "RSI": "", "R8": "", "R9": "", "R10": "",
                        "R11": "", "R12": "", "R13": "", "R14": "",
                        "R15": "", "RBP": "", "RSP": "", "RIP": ""}

    def addFunction(self, function):
        self.functions[function.name] = function

    def addVulnerability(self, vulnerability):
        self.vulnerabilities.append(vulnerability)

    def execute(self):
        self.functions['main'].execute(self)
