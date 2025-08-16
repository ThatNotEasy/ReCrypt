from modules.zgpriv import ZGPRIV
import os, time

def main():
    zgpriv = ZGPRIV()
    zgpriv.analyzer_zgpriv()
    
if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    main()