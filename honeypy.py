
#Libraries
import argparse
from ssh_honeypot import *
from web_honeypot import *


#Parse Arguments

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--address', type = str, required = True) #supply ip address
    parser.add_argument('-p', '--port', type = int, required = True) #supply port number
    parser.add_argument('-u', '--username', type = str) #supply username
    parser.add_argument('-pw', '--password', type = str) #supply password

    parser.add_argument('-s', '--ssh', action='store_true') 
    parser.add_argument('-w', '--http', action='store_true')

    args = parser.parse_args() #Combines all arguments into one variable

    try:
        if args.ssh:
            print("[-]  Running SSH honeypot...")
            honeypot(args.address, args.port, args.username, args.password)

            if not args.username:
                username = None
            if not args.password:
                password = None
        elif args.http:
            print("[-]  Running HTTP honeypot...")
            if not args.username:
                args.username = "admin"
            if not args.password:
                args.password = "password"
            
            print(f"Port number: {args.port}, Username: {args.username}, Password: {args.password}")
            run_web_honeypot(args.port, args.username, args.password)
            pass
        else:
            print("[!]  Please specify a honeypot type (SSH or HTTP).")
    except:
        print("\n Exiting Honeypy...\n")