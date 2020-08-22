# coding=utf-8
import nmap

scanner = nmap.PortScanner()

print ('Seja bem vindo ao DIOScanner')
print("<---------------------------->")

ip = str(input("Digite o IP a ser varrido: "))
print("O IP digitado foi: ", str(ip))
type(ip)
menu = input(""""\n Escolha o tipo de varredura a ser realizada
             1 -> Varredura do tipo SYN
             2 -> Varredura do tipo UDP
             3 -> Varredura do tipo Intensa
             Digite a opcão escolhida :""")

print("A opcao escolhida foi: ", menu)

if menu == "1":
    print ("versao do Nmap: ", scanner.nmap_version())
    scanner.scan(ip, '1-1024', '-v -sT')
    print (scanner.scaninfo())
    print("Status do IP: ", scanner[ip].state())
    print (scanner[ip].all_protocols())
    print(" ")
    print("Portas abertas: ", scanner[ip]['tcp'].Keys())
elif menu == "2":
    print ("versao do Nmap: ", scanner.nmap_version())
    scanner.scan(ip, '1-1024', '-v -sU')
    print (scanner.scaninfo())
    print("Status do IP: ", scanner[ip].state())
    print (scanner[ip].all_protocols())
    print(" ")
    print("Portas abertas: ", scanner[ip]['udp'].Keys())
elif menu == "3":
    print ("versao do Nmap: ", scanner.nmap_version())
    scanner.scan(ip, '1-1024', '-v -sC')
    print (scanner.scaninfo())
    print("Status do IP: ", scanner[ip].state())
    print (scanner[ip].all_protocols())
    print(" ")
    print("Portas abertas: ", scanner[ip]['tcp'].Keys())
else:
    print ("Escolha uma opcao correta!")






