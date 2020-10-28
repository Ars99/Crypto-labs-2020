import matplotlib.pyplot as plt
import numpy as np
# from main import time_1, time_2, length


time_1 = [0.00020889449119567872, 0.0016435282230377198, 0.01587982201576233, 1.582172656059265]
time_2 = [2.451324462890625e-05, 4.0890693664550784e-05, 0.00029421329498291015, 0.030492753744125366]
length = [0.1, 1, 10, 1024]

def graph_1():
    plt.title("Зависимость времени от длины сообщения")
    plt.plot(length, time_1, color='blue', marker='o', linestyle='--', markerfacecolor='blue', label='OMAC')
    plt.grid()
    plt.savefig('time_memory_1.png')
    plt.show()

def graph_2():
    plt.title("Зависимость времени от длины сообщения")
    plt.plot(length, time_2, color='red', marker='o', linestyle='--', markerfacecolor='red', label='HMAC')
    plt.grid()
    plt.savefig('time_memory_2.png')
    plt.show()

graph_1()
graph_2()

