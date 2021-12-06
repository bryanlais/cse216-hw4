from serverattackdetector import ServerAttackDetector

d = ServerAttackDetector("hw4testfile.csv")  # to be replaced by actual path
a, b = d.detect()
print(a)  # to verify whether your code is, indeed, performing lazy evaluation
print(b)  # to verify whether your code is, indeed, able to detect the first
          # instance of a potential attack
