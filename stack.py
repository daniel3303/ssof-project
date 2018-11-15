#Stack class

class Stack:
    def __init__(self, function):
        self.function = function

        #Checks if the function argument is from type Function
        if(!issubclass(function, Function)):
            raise Error("Invalid argument type.")


    def getFunction(self):
        return self.function


class StackManager:
    def __init__(self, function):
        self.stacks = []

    def createStack(self):
        self.stacks.append(Stack())
        return True


    # Removes and returns the last element from the stacks lists.
    # @Return None if empty
    def popStack(self):
        if len(self.stacks) < 1:
            return None

        return self.stacks.pop()
