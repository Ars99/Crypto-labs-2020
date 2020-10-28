import matplotlib.pyplot as plt
import numpy as np
from main import total_memory, memory_birthday, num_of_sha


def graph_birth():
    for i in range(15, 21):
        memory_birthday.append(total_memory(i))
    plt.title("Зависимость памяти от размера выхода хэш-функции")
    plt.plot(num_of_sha, memory_birthday, color='red', marker='o', linestyle='--', markerfacecolor='blue')
    plt.grid()
    plt.savefig('birth_memory.png')
    plt.show()

graph_birth()


