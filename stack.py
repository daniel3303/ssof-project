#Stack class

class Stack:
    def __init__(self, function):
        self.function = function

        #Checks if the function argument is from type Function
        if(!issubclass(function, Function)):
            raise Error("Invalid argument type.")


    def getFunction(self):
        return self.function
