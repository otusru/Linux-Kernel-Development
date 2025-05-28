## **Основы ядра Linux**  

### **1. Что такое ядро Linux? Основные функции**  

**Ядро Linux** — это центральная часть операционной системы, которая управляет ресурсами компьютера, обеспечивает взаимодействие между аппаратурой и программами.  

**Основные функции:**  
1. **Управление процессами** — создание, планирование, синхронизация.  
2. **Управление памятью** — виртуальная память, кэширование, swap.  
3. **Файловые системы** — работа с дисками, сетевые ФС (NFS, ext4).  
4. **Управление устройствами** — драйверы, ввод-вывод.  
5. **Сетевой стек** — обработка TCP/IP, фильтрация пакетов.  
6. **Безопасность** — права доступа, SELinux, capabilities.  

---

## **1. Управление процессами**  
**Функции:**  
- Создание процессов (`fork`, `clone`).  
- Планирование выполнения (CPU scheduler).  
- Синхронизация (мьютексы, спинлоки).  

### **Примеры из исходников**  
#### **Структура процесса (`task_struct`)**  
```c
// include/linux/sched.h
struct task_struct {
    volatile long state;            // Состояние (TASK_RUNNING, STOPPED...)
    void *stack;                    // Указатель на стек
    struct mm_struct *mm;           // Управление памятью
    pid_t pid;                      // Идентификатор процесса
    struct task_struct *parent;     // Родительский процесс
    struct list_head children;      // Список дочерних процессов
    // ... +500 других полей ...
};
```

#### **Системный вызов `fork()`**  
```c
// kernel/fork.c
long _do_fork(unsigned long clone_flags) {
    struct task_struct *p;
    p = copy_process(clone_flags, 0, 0, NULL, NULL, 0);
    wake_up_new_task(p);  // Добавляем процесс в планировщик
    return p->pid;
}
```

**Схема состояний процесса:**  
```
+-----------------+
|     TASK_RUNNING  | ← Процесс выполняется или в очереди
+-----------------+
        ↓
+-----------------+
|   TASK_INTERRUPTIBLE | ← Ожидает события (например, ввода)
+-----------------+
        ↓
+-----------------+
|    TASK_STOPPED    | ← Приостановлен (Ctrl+Z)
+-----------------+
```

---

## **2. Управление памятью**  
**Функции:**  
- Виртуальная память (paging, MMU).  
- Выделение памяти (`kmalloc`, `vmalloc`).  
- Подкачка (swapping).  

### **Примеры из исходников**  
#### **Структура виртуальной памяти (`mm_struct`)**  
```c
// include/linux/mm_types.h
struct mm_struct {
    struct vm_area_struct *mmap;    // Список VMA (областей памяти)
    pgd_t *pgd;                    // Таблица страниц (Page Global Directory)
    atomic_t mm_users;              // Количество пользователей
    // ...
};
```

#### **Выделение памяти в ядре**  
```c
// mm/slab.c (для kmalloc)
void *kmalloc(size_t size, gfp_t flags) {
    return __kmalloc(size, flags);
}

// mm/vmalloc.c (для больших областей)
void *vmalloc(unsigned long size) {
    return __vmalloc(size, GFP_KERNEL, PAGE_KERNEL);
}
```

**Таблица: `kmalloc` vs `vmalloc`**  
| **Критерий**   | `kmalloc`                  | `vmalloc`                  |
|---------------|---------------------------|---------------------------|
| **Физическая память** | Непрерывная           | Может быть разрозненной   |
| **Размер**    | До нескольких MB         | Огромные регионы          |
| **Использование** | DMA, быстрые структуры | Крупные буферы           |

---

## **3. Файловые системы**  
**Функции:**  
- Виртуальная файловая система (VFS).  
- Реализация операций (`open`, `read`, `write`).  

### **Примеры из исходников**  
#### **Структура VFS (`inode`, `file`)**  
```c
// include/linux/fs.h
struct inode {
    umode_t i_mode;         // Права доступа (rwx)
    loff_t i_size;          // Размер файла
    struct file_operations *i_fop;  // Операции (read, write)
};

struct file {
    struct path f_path;      // Путь к файлу
    const struct file_operations *f_op;  // Методы работы
};
```

#### **Системный вызов `read()`**  
```c
// fs/read_write.c
ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count) {
    struct file *file = fget(fd);
    return vfs_read(file, buf, count, &file->f_pos);
}
```

**Схема VFS:**  
```
+------------------+
|   Приложение (read())  |
+------------------+
         ↓
+------------------+
|      VFS Layer       | ← Общий интерфейс (file_operations)
+------------------+
         ↓
+------------------+
| Конкретная ФС (ext4) | ← Реализация для ext4, NTFS...
+------------------+
```

---

## **4. Управление устройствами**  
**Функции:**  
- Драйверы устройств (символьные, блочные).  
- Ввод-вывод (I/O ports, DMA).  

### **Примеры из исходников**  
#### **Регистрация драйвера**  
```c
// drivers/char/mem.c (пример нулевого устройства)
static const struct file_operations zero_fops = {
    .read = read_zero,  // Чтение всегда возвращает 0
    .write = write_zero,
};

static int __init zero_init(void) {
    register_chrdev(MEM_MAJOR, "null", &zero_fops);
}
```

**Таблица типов устройств:**  
| **Тип**        | **Пример**       | **Интерфейс**          |
|---------------|------------------|-----------------------|
| **Символьное** | `/dev/tty`, `/dev/null` | `file_operations` |
| **Блочное**    | `/dev/sda`       | `block_device_operations` |
| **Сетевое**    | `eth0`           | `net_device`         |

---

## **5. Сетевой стек**  
**Функции:**  
- Обработка пакетов (TCP/IP, UDP).  
- Фильтрация (Netfilter, iptables).  

### **Примеры из исходников**  
#### **Структура сетевого пакета (`sk_buff`)**  
```c
// include/linux/skbuff.h
struct sk_buff {
    struct net_device *dev;  // Устройство-отправитель
    __u32 ip_summed;        // Контрольная сумма
    unsigned char *data;     // Данные пакета
};
```

#### **Фильтрация пакетов (Netfilter)**  
```c
// net/ipv4/netfilter.c
static unsigned int nf_hook(void *priv, struct sk_buff *skb) {
    if (ipt_do_table(skb, NF_INET_LOCAL_IN, NULL) == DROP)
        return NF_DROP;
    return NF_ACCEPT;
}
```

**Схема пути пакета:**  
```
+------------------+
|   Сетевой интерфейс   | ← Получение пакета
+------------------+
         ↓
+------------------+
|   IP-роутинг       | ← Решение, куда направить
+------------------+
         ↓
+------------------+
|   TCP/UDP         | ← Обработка транспортного уровня
+------------------+
         ↓
+------------------+
|   Приложение (socket) | ← Доставка данных
+------------------+
```

---

## **6. Безопасность**  
**Функции:**  
- Механизмы контроля доступа (SELinux, capabilities).  
- Защита памяти (KASLR, SMAP).  

### **Примеры из исходников**  
#### **Проверка прав (`capabilities`)**  
```c
// security/commoncap.c
int capable(int cap) {
    return ns_capable(current_user_ns(), cap);
}
```

**Таблица защиты ядра:**  
| **Механизм**      | **Описание**                          | **Пример использования**          |
|------------------|-------------------------------------|----------------------------------|
| **KASLR**        | Рандомизация адресов ядра           | Затрудняет эксплойты             |
| **SMAP**         | Запрет доступа к user-space из ядра | `mov %rax, [user_ptr]` → PANIC! |
| **SELinux**      | Мандатное управление доступом       | Политики для процессов          |

---

✅ Примеры кода из ядра Linux.
✅ Схемы работы подсистем.
✅ Таблицы сравнения механизмов.

**Что дальше?**  
1. Скомпилируйте ядро с `CONFIG_DEBUG_INFO` для отладки.  
2. Используйте `strace` и `ftrace` для анализа системных вызовов.  
3. Напишите свой LKM (Loadable Kernel Module).  

## **1. Скомпилируйте ядро с `CONFIG_DEBUG_INFO` для отладки**  
**Цель:** Собрать ядро Linux с отладочной информацией для использования в `gdb`, `kgdb` или других инструментах.  

### **Шаги:**  

#### **1. Установка зависимостей**  
```bash
sudo apt update
sudo apt install build-essential libncurses-dev bison flex libssl-dev libelf-dev
```

#### **2. Скачивание исходников ядра**  
Выберите версию на [kernel.org](https://kernel.org) или используйте текущую:  
```bash
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz
tar -xvf linux-6.6.tar.xz
cd linux-6.6
```

#### **3. Настройка конфигурации**  
```bash
make menuconfig
```
В меню:  
1. Перейдите в `Kernel hacking` → `Compile-time checks and compiler options`.  
2. Включите:  
   - `CONFIG_DEBUG_INFO=y` (для символов отладки).  
   - `CONFIG_GDB_SCRIPTS=y` (для удобной отладки в `gdb`).  
3. Сохраните конфиг (`.config`).

#### **4. Компиляция ядра**  
```bash
make -j$(nproc)  # Используйте все ядра CPU
```
Готовые файлы:  
- `vmlinux` (ядро с символами).  
- `arch/x86/boot/bzImage` (сжатый образ для загрузки).  

#### **5. Установка нового ядра**  
```bash
sudo make modules_install
sudo make install
sudo update-grub
```
Перезагрузитесь:  
```bash
sudo reboot
```

#### **6. Проверка**  
```bash
uname -r  # Должна отобразиться ваша версия (6.6)
```

---

## **2. Используйте `strace` и `ftrace` для анализа системных вызовов**  

### **Анализ системных вызовов с `strace`**  
**Пример:** Просмотр вызовов команды `ls`:  
```bash
strace ls /tmp
```
**Ключевые опции:**  
- `-p PID` — прикрепиться к процессу.  
- `-e trace=open,read` — фильтр по вызовам.  
- `-o log.txt` — запись в файл.  

### **Трассировка ядра с `ftrace`**  
**Шаги:**  
1. Активируйте `ftrace`:  
   ```bash
   cd /sys/kernel/debug/tracing
   echo function_graph > current_tracer
   ```
2. Задайте фильтр (например, только системные вызовы):  
   ```bash
   echo "sys_*" > set_ftrace_filter
   ```
3. Запустите трассировку:  
   ```bash
   echo 1 > tracing_on
   ```
4. Выполните команду (например, `ls`).  
5. Остановите трассировку и просмотрите логи:  
   ```bash
   echo 0 > tracing_on
   cat trace | less
   ```

**Пример вывода `ftrace`:**  
```
# tracer: function_graph
# CPU  DURATION            FUNCTION CALLS
  1)   0.120 us    |  sys_open();
  1)   0.310 us    |  sys_read();
```

---

## **3. Напишите свой LKM (Loadable Kernel Module)**  
**Цель:** Создать простой модуль ядра, который выводит сообщение при загрузке/выгрузке.  

### **Шаги:**  

#### **1. Создание файла модуля**  
`hello.c`:  
```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Simple LKM example");

static int __init hello_init(void) {
    printk(KERN_INFO "Hello, Kernel World!\n");
    return 0;
}

static void __exit hello_exit(void) {
    printk(KERN_INFO "Goodbye, Kernel World!\n");
}

module_init(hello_init);
module_exit(hello_exit);
```

#### **2. Создание `Makefile`**  
```makefile
obj-m := hello.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
    make -C $(KDIR) M=$(PWD) modules

clean:
    make -C $(KDIR) M=$(PWD) clean
```

#### **3. Компиляция модуля**  
```bash
make
```
После успеха появится файл `hello.ko`.

#### **4. Загрузка модуля**  
```bash
sudo insmod hello.ko
```
Проверка вывода:  
```bash
dmesg | tail -n 1  # Должно показать "Hello, Kernel World!"
```

#### **5. Выгрузка модуля**  
```bash
sudo rmmod hello
dmesg | tail -n 1  # "Goodbye, Kernel World!"
```

#### **6. Дополнительно: передача параметров в модуль**  
Модифицируйте `hello.c`:  
```c
static char *name = "User";
module_param(name, charp, 0);
MODULE_PARM_DESC(name, "Name to greet");

static int __init hello_init(void) {
    printk(KERN_INFO "Hello, %s!\n", name);
    return 0;
}
```
Загрузка с параметром:  
```bash
sudo insmod hello.ko name="Alice"
```

---

## **Итог**  
Теперь вы можете:  
✅ Собирать ядро с отладочной информацией.  
✅ Анализировать системные вызовы через `strace` и `ftrace`.  
✅ Создавать и загружать свои модули ядра.  

**Следующие шаги:**  
1. Добавьте в модуль работу с `/proc` или `sysfs`.  
2. Напишите простой драйвер символьного устройства.  
3. Используйте `gdb` для отладки ядра.  

---

## **1. Добавление работы с `/proc` или `sysfs` в модуль ядра**  
**Цель:** Создать файл в `/proc` или `/sys`, через который можно читать/писать данные из пользовательского пространства.

### **Вариант 1: Интерфейс `/proc`**  
#### Шаги:
1. **Модифицируем `hello.c`** (добавляем `/proc/hello_world`):
    ```c
    #include <linux/proc_fs.h>
    #include <linux/seq_file.h>

    static struct proc_dir_entry *proc_entry;

    static int proc_show(struct seq_file *m, void *v) {
        seq_printf(m, "Hello from /proc!\n");
        return 0;
    }

    static int proc_open(struct inode *inode, struct file *file) {
        return single_open(file, proc_show, NULL);
    }

    static const struct proc_ops proc_fops = {
        .proc_open = proc_open,
        .proc_read = seq_read,
        .proc_release = single_release,
    };

    static int __init hello_init(void) {
        proc_entry = proc_create("hello_world", 0, NULL, &proc_fops);
        if (!proc_entry) return -ENOMEM;
        printk(KERN_INFO "/proc/hello_world created\n");
        return 0;
    }

    static void __exit hello_exit(void) {
        proc_remove(proc_entry);
        printk(KERN_INFO "/proc/hello_world removed\n");
    }
    ```
2. **Перекомпилируем и загружаем модуль**:
    ```bash
    make
    sudo insmod hello.ko
    ```
3. **Проверяем**:
    ```bash
    cat /proc/hello_world  # Должно вывести "Hello from /proc!"
    sudo rmmod hello
    ```

### **Вариант 2: Интерфейс `sysfs`**  
#### Шаги:
1. **Модифицируем `hello.c`** (добавляем `/sys/kernel/hello/value`):
    ```c
    #include <linux/kobject.h>
    #include <linux/sysfs.h>

    static int value = 0;
    static struct kobject *hello_kobj;

    static ssize_t value_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
        return sprintf(buf, "%d\n", value);
    }

    static ssize_t value_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
        sscanf(buf, "%d", &value);
        return count;
    }

    static struct kobj_attribute value_attr = __ATTR(value, 0664, value_show, value_store);

    static int __init hello_init(void) {
        hello_kobj = kobject_create_and_add("hello", kernel_kobj);
        if (sysfs_create_file(hello_kobj, &value_attr.attr)) {
            kobject_put(hello_kobj);
            return -ENOMEM;
        }
        return 0;
    }

    static void __exit hello_exit(void) {
        kobject_put(hello_kobj);
    }
    ```
2. **Проверяем**:
    ```bash
    echo 42 | sudo tee /sys/kernel/hello/value  # Запись
    cat /sys/kernel/hello/value                 # Чтение (должно быть 42)
    ```

---

## **2. Написание простого драйвера символьного устройства**  
**Цель:** Создать драйвер для устройства `/dev/hello`, поддерживающего операции `read`/`write`.

### **Шаги:**
1. **Создаём `chardev.c`**:
    ```c
    #include <linux/fs.h>
    #include <linux/cdev.h>
    #include <linux/uaccess.h>

    #define DEVICE_NAME "hello"
    static int major;
    static char msg[100] = {0};
    static struct cdev hello_cdev;

    static int hello_open(struct inode *inode, struct file *file) {
        printk(KERN_INFO "Device opened\n");
        return 0;
    }

    static ssize_t hello_read(struct file *file, char __user *buf, size_t len, loff_t *offset) {
        int res = copy_to_user(buf, msg, len);
        return res ? -EFAULT : len;
    }

    static ssize_t hello_write(struct file *file, const char __user *buf, size_t len, loff_t *offset) {
        copy_from_user(msg, buf, len);
        return len;
    }

    static const struct file_operations fops = {
        .open = hello_open,
        .read = hello_read,
        .write = hello_write,
    };

    static int __init chardev_init(void) {
        major = register_chrdev(0, DEVICE_NAME, &fops);
        cdev_init(&hello_cdev, &fops);
        cdev_add(&hello_cdev, MKDEV(major, 0), 1);
        printk(KERN_INFO "Device registered with major=%d\n", major);
        return 0;
    }

    static void __exit chardev_exit(void) {
        cdev_del(&hello_cdev);
        unregister_chrdev(major, DEVICE_NAME);
    }

    module_init(chardev_init);
    module_exit(chardev_exit);
    ```
2. **Компилируем и загружаем**:
    ```bash
    make
    sudo insmod chardev.ko
    ```
3. **Создаём устройство и проверяем**:
    ```bash
    sudo mknod /dev/hello c $(grep hello /proc/devices | awk '{print $1}') 0
    sudo chmod 666 /dev/hello
    echo "Test" > /dev/hello  # Запись
    cat /dev/hello            # Чтение (должно вывести "Test")
    ```

---

## **3. Использование `gdb` для отладки ядра**  
**Цель:** Настроить отладку ядра через `gdb` с использованием `QEMU` или реального оборудования.

### **Шаги для QEMU:**
1. **Установите QEMU и зависимости**:
    ```bash
    sudo apt install qemu-system-x86 gdb
    ```
2. **Запустите ядро в QEMU** (с отладочным режимом):
    ```bash
    qemu-system-x86_64 -kernel /path/to/bzImage -initrd /path/to/initramfs.img -s -S
    ```
   - `-s` — открывает порт `1234` для `gdb`.
   - `-S` — останавливает выполнение до подключения отладчика.
3. **Подключите `gdb`**:
    ```bash
    gdb vmlinux
    (gdb) target remote :1234
    (gdb) break start_kernel  # Установите точку останова
    (gdb) continue
    ```
4. **Пример отладки модуля**:
    ```bash
    (gdb) break hello_init     # Точка останова в модуле
    (gdb) continue
    ```

### **Шаги для реального ядра (с `kgdb`)**:
1. **Добавьте в аргументы ядра при загрузке**:
    ```bash
    kgdbwait kgdboc=ttyS0,115200
    ```
2. **Подключитесь с другой машины через `gdb`**:
    ```bash
    gdb vmlinux
    (gdb) target remote /dev/ttyUSB0
    ```

---

## **Итог**  
Теперь вы можете:  
✅ Добавлять интерфейсы `/proc` и `sysfs` в модули.  
✅ Создавать драйверы символьных устройств.  
✅ Отлаживать ядро через `gdb` в QEMU или на реальном железе.  

**Что дальше:**  
1. Добавьте `ioctl` в драйвер для расширенного управления.  
2. Изучите `kprobes` для трассировки функций ядра.  
3. Попробуйте отладить обработку прерываний.  

### **1. Добавление `ioctl` в драйвер для расширенного управления**  
**Цель:** Реализовать в драйвере символьного устройства команды для управления устройством через `ioctl`.  

#### **Шаги:**  

##### **1. Модификация драйвера (`chardev.c`)**  
Добавим поддержку `ioctl` для:  
- **Чтения** текущего значения из драйвера.  
- **Записи** нового значения.  

```c
#include <linux/ioctl.h>

// Определяем магическое число и команды
#define HELLO_MAGIC 'H'
#define HELLO_GET_VALUE _IOR(HELLO_MAGIC, 1, int)
#define HELLO_SET_VALUE _IOW(HELLO_MAGIC, 2, int)

static int value = 0;  // Переменная для хранения значения

static long hello_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case HELLO_GET_VALUE:
            if (copy_to_user((int __user *)arg, &value, sizeof(int)))
                return -EFAULT;
            break;
        case HELLO_SET_VALUE:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int)))
                return -EFAULT;
            break;
        default:
            return -ENOTTY;  // Неизвестная команда
    }
    return 0;
}

// Обновляем структуру file_operations
static const struct file_operations fops = {
    .open = hello_open,
    .read = hello_read,
    .write = hello_write,
    .unlocked_ioctl = hello_ioctl,  // Добавляем обработчик ioctl
};
```

##### **2. Компиляция и загрузка драйвера**  
```bash
make
sudo insmod chardev.ko
sudo chmod 666 /dev/hello  # Даём права на чтение/запись
```

##### **3. Тестирование `ioctl`**  
Создадим тестовую программу (`test_ioctl.c`):  
```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define HELLO_MAGIC 'H'
#define HELLO_GET_VALUE _IOR(HELLO_MAGIC, 1, int)
#define HELLO_SET_VALUE _IOW(HELLO_MAGIC, 2, int)

int main() {
    int fd = open("/dev/hello", O_RDWR);
    int val = 42;

    // Устанавливаем значение
    ioctl(fd, HELLO_SET_VALUE, &val);

    // Читаем значение
    ioctl(fd, HELLO_GET_VALUE, &val);
    printf("Current value: %d\n", val);

    close(fd);
    return 0;
}
```
**Компиляция и запуск:**  
```bash
gcc test_ioctl.c -o test_ioctl
./test_ioctl  # Должно вывести "Current value: 42"
```

---

### **2. Изучение `kprobes` для трассировки функций ядра**  
**Цель:** Использовать `kprobes` для перехвата вызовов функций ядра (например, `printk`).  

#### **Шаги:**  

##### **1. Написание модуля с `kprobe`**  
Создаём `kprobe_example.c`:  
```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

static struct kprobe kp = {
    .symbol_name = "printk",  // Функция для перехвата
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    pr_info("printk called with message: %s\n", (char *)regs->di);
    return 0;
}

static int __init kprobe_init(void) {
    kp.pre_handler = handler_pre;
    register_kprobe(&kp);
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp);
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
```

##### **2. Компиляция и загрузка**  
```bash
make
sudo insmod kprobe_example.ko
```

##### **3. Проверка**  
Вызовите любую команду, использующую `printk` (например, `dmesg`):  
```bash
dmesg | tail  # Увидите перехваченные вызовы printk
```

##### **4. Важные моменты**  
- `kprobes` работает только для экспортированных символов ядра (проверьте `/proc/kallsyms`).  
- Для функций с параметрами используйте регистры (`regs->di` для 1-го аргумента в x86_64).  

---

### **3. Отладка обработки прерываний**  
**Цель:** Настроить обработку прерывания от аппаратного устройства (например, кнопки) и отладить его.  

#### **Шаги:**  

##### **1. Регистрация обработчика прерывания**  
Пример для виртуального прерывания (для реального устройства используйте IRQ из `/proc/interrupts`):  
```c
#include <linux/interrupt.h>

static irqreturn_t irq_handler(int irq, void *dev_id) {
    pr_info("Interrupt %d triggered!\n", irq);
    return IRQ_HANDLED;
}

static int __init irq_example_init(void) {
    int irq = 1;  // Например, IRQ1 (клавиатура)
    if (request_irq(irq, irq_handler, IRQF_SHARED, "example_irq", NULL)) {
        pr_err("Failed to request IRQ %d\n", irq);
        return -EIO;
    }
    return 0;
}

static void __exit irq_example_exit(void) {
    free_irq(1, NULL);
}

module_init(irq_example_init);
module_exit(irq_example_exit);
```

##### **2. Отладка прерывания**  
- **Способ 1: Логирование**  
  Используйте `printk` в обработчике, затем смотрите `dmesg`.  

- **Способ 2: `kgdb`**  
  1. Запустите ядро в QEMU с `-s -S`.  
  2. Подключите `gdb` и установите точку останова:  
     ```bash
     (gdb) break irq_handler
     (gdb) continue
     ```  
  3. Имитируйте прерывание (например, нажмите клавишу в QEMU).  

##### **3. Важные моменты**  
- Прерывания должны обрабатываться **быстро** (нельзя использовать `sleep` или блокирующие вызовы).  
- Для отладки реального железа используйте логирование или JTAG.  

---

## **Итог**  
Теперь вы можете:  
✅ Добавлять `ioctl` в драйверы для расширенного управления.  
✅ Использовать `kprobes` для трассировки функций ядра.  
✅ Отлаживать обработку прерываний.  

**Что дальше:**  
1. Реализуйте **DMA** в драйвере для высокоскоростного обмена данными.  
2. Изучите **eBPF** для безопасной трассировки ядра без модулей.  
3. Попробуйте **оптимизировать** обработчик прерываний.  

### **1. Реализация DMA в драйвере для высокоскоростного обмена данными**  
**Цель:** Настроить прямой доступ к памяти (DMA) для передачи данных между устройством и RAM без участия CPU.  

#### **Шаги:**  

##### **1. Подготовка DMA-буфера**  
Модифицируем драйвер (`dma_driver.c`):  
```c
#include <linux/dma-mapping.h>

#define BUF_SIZE 4096
static char *dma_buf;
static dma_addr_t dma_handle;

static int __init dma_init(void) {
    // Выделяем DMA-буфер (когерентная память)
    dma_buf = dma_alloc_coherent(NULL, BUF_SIZE, &dma_handle, GFP_KERNEL);
    if (!dma_buf) return -ENOMEM;
    
    printk(KERN_INFO "DMA buffer allocated at phys: 0x%llx\n", dma_handle);
    return 0;
}

static void __exit dma_exit(void) {
    dma_free_coherent(NULL, BUF_SIZE, dma_buf, dma_handle);
}
```

##### **2. Настройка DMA-канала**  
Для реального устройства (например, PCI):  
```c
struct dma_chan *chan;
chan = dma_request_chan(&pdev->dev, "tx");
if (IS_ERR(chan)) return PTR_ERR(chan);

struct dma_async_tx_descriptor *tx;
tx = chan->device->device_prep_dma_memcpy(chan, dest_dma, src_dma, size, 0);
dmaengine_submit(tx);
dma_async_issue_pending(chan);
```

##### **3. Тестирование**  
1. Загрузите модуль:  
   ```bash
   sudo insmod dma_driver.ko
   dmesg | tail  # Проверьте адрес DMA-буфера
   ```
2. Используйте `mmap` для доступа к буферу из userspace (если нужно).  

---

### **2. Изучение eBPF для трассировки ядра**  
**Цель:** Использовать eBPF для мониторинга системных вызовов без написания модулей ядра.  

#### **Шаги:**  

##### **1. Установка инструментов eBPF**  
```bash
sudo apt install bpftrace bpfcc-tools linux-headers-$(uname -r)
```

##### **2. Пример трассировки вызовов `open()`**  
Создайте скрипт (`trace_open.bt`):  
```bash
#!/usr/bin/bpftrace

tracepoint:syscalls:sys_enter_open {
    printf("%s called open(%s)\n", comm, str(args->filename));
}
```
Запустите:  
```bash
sudo bpftrace trace_open.bt
```

##### **3. Мониторинг событий ядра**  
```bash
# Трассировка всех вызовов kmalloc
sudo funccount 'kmalloc'
```

##### **4. Использование BCC**  
Пример (`trace_reads.py`):  
```python
from bcc import BPF

bpf = BPF(text='''
int kprobe__vfs_read(struct pt_regs *ctx) {
    bpf_trace_printk("File read\\n");
    return 0;
}
''')
bpf.trace_print()
```

---

### **3. Оптимизация обработчика прерываний**  
**Цель:** Уменьшить задержки в обработчике прерываний (IRQ).  

#### **Шаги:**  

##### **1. Перенос тяжелой логики в `tasklet` или `workqueue`**  
```c
#include <linux/interrupt.h>
#include <linux/workqueue.h>

static DECLARE_WORK(work_handler, void *data);

static irqreturn_t irq_handler(int irq, void *dev_id) {
    schedule_work(&work_handler);  // Переносим обработку в контекст процесса
    return IRQ_HANDLED;
}

static void work_handler(void *data) {
    // Медленная обработка (например, парсинг данных)
    printk(KERN_INFO "Workqueue: Data processed\n");
}
```

##### **2. Использование `softirq` для высокоприоритетных задач**  
```c
static void softirq_handler(struct softirq_action *sa) {
    printk(KERN_INFO "SoftIRQ: Fast processing\n");
}

static int __init irq_init(void) {
    open_softirq(MY_SOFTIRQ, softirq_handler);
    return 0;
}
```

##### **3. Проверка задержек**  
Инструменты:  
- `ftrace`:  
  ```bash
  echo function_graph > /sys/kernel/debug/tracing/current_tracer
  echo irq_handler > /sys/kernel/debug/tracing/set_ftrace_filter
  cat /sys/kernel/debug/tracing/trace_pipe
  ```
- `perf`:  
  ```bash
  sudo perf stat -e irq:irq_handler_entry -a sleep 1
  ```

---

## **Итог**  
Теперь вы можете:  
✅ Реализовать **DMA** для высокоскоростного обмена данными.  
✅ Использовать **eBPF** для безопасной трассировки ядра.  
✅ Оптимизировать **обработчики прерываний** для минимальных задержек.  

**Что дальше:**  
1. **Реализуйте scatter-gather DMA** для работы с разрозненными буферами.  
2. **Напишите eBPF-программу** для фильтрации сетевых пакетов.  
3. **Профилируйте IRQ** с помощью `perf top` и найдите узкие места.  

Для углубленного изучения смотрите:  
- [Документация DMA](https://www.kernel.org/doc/html/latest/core-api/dma-api.html)  
- [eBPF Examples](https://github.com/iovisor/bcc)  
- [Linux Kernel Performance](https://brendangregg.com/linuxperf.html)  


---
---
---

**Пример из исходников:**  
Структура `task_struct` (описывает процесс в ядре):  
```c
// include/linux/sched.h
struct task_struct {
    volatile long state;            // состояние процесса (R, S, D, Z)
    struct mm_struct *mm;           // управление памятью
    pid_t pid;                      // идентификатор процесса
    struct list_head tasks;         // список процессов
    // ... сотни других полей ...
};
```

---

### **2. Монолитное ядро vs Микроядро. Почему Linux — гибридное?**  

| **Критерий**       | **Монолитное ядро**               | **Микроядро**                     | **Linux (гибрид)**                |
|--------------------|-----------------------------------|-----------------------------------|-----------------------------------|
| **Архитектура**    | Все компоненты в одном адресном пространстве | Только базовые функции в ядре, остальное в user-space | Основные части в ядре, но модули могут загружаться динамически |
| **Производительность** | Высокая (меньше переключений) | Низкая (много IPC)               | Высокая (оптимизированные механизмы) |
| **Надёжность**     | Ошибка может уронить всю ОС       | Отказ компонента не затрагивает ядро | Критические части защищены |
| **Примеры**        | Linux, FreeBSD                    | QNX, MINIX                       | Linux с модулями (`*.ko`) |

**Почему Linux гибридное?**  
- Основные компоненты (планировщик, сетевой стек) работают в kernel-space.  
- Драйверы и некоторые подсистемы могут быть вынесены в модули (`*.ko`), которые загружаются динамически.  

**Пример модуля ядра:**  
```c
// hello_kernel.c
#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

static int __init hello_init(void) {
    printk(KERN_INFO "Hello, Kernel!\n");
    return 0;
}

static void __exit hello_exit(void) {
    printk(KERN_INFO "Goodbye, Kernel!\n");
}

module_init(hello_init);
module_exit(hello_exit);
```
Сборка:  
```bash
obj-m += hello_kernel.o
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```

---

### **3. Загрузка ядра: от BIOS/UEFI до `init`**  

**Схема загрузки:**  
```
BIOS/UEFI → Загрузчик (GRUB) → Ядро (vmlinuz) → Initramfs → Монтирование корневой ФС → Запуск /sbin/init (systemd)
```

**Этапы:**  
1. **BIOS/UEFI** — ищет загрузочное устройство, загружает **GRUB**.  
2. **GRUB** — загружает ядро (`vmlinuz`) и `initramfs` (временная ФС).  
3. **Ядро** — инициализирует CPU, память, драйверы, монтирует корневую ФС.  
4. **Init** — запускается первая программа (`systemd` или `init`).  

**Пример из исходников (инициализация ядра):**  
```c
// init/main.c
void __init start_kernel(void) {
    setup_arch();           // архитектурно-зависимая инициализация
    mm_init();              // управление памятью
    sched_init();           // планировщик
    rest_init();            // запуск init-процесса
}
```

---

### **4. User-space vs Kernel-space**  

**Схема:**  
```
+---------------------+
|   Приложения (bash, gcc)  |  → User-space (Ring 3)
+---------------------+
|       GLIBC         |  → Интерфейс системных вызовов (syscalls)
+---------------------+
|       Ядро          |  → Kernel-space (Ring 0)
+---------------------+
|   Железо (CPU, RAM) |
+---------------------+
```

**Ключевые отличия:**  
| **Критерий**        | **User-space**               | **Kernel-space**              |
|---------------------|-----------------------------|-------------------------------|
| **Уровень привилегий** | Ring 3 (ограниченный)     | Ring 0 (полный доступ)       |
| **Доступ к памяти** | Только своя виртуальная     | Вся физическая память        |
| **Ошибки**          | Убивают процесс             | Убивают всю систему (oops/panic) |
| **Примеры**         | Bash, Python               | Драйверы, файловые системы   |

**Пример системного вызова (`open`):**  
```c
// fs/open.c
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode) {
    return do_sys_open(AT_FDCWD, filename, flags, mode);
}
```
При вызове `open()` в user-space происходит переход в kernel-mode через инструкцию `syscall`.  

---
