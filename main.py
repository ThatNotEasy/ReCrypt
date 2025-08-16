from modules.zgpriv import ZGPRIV
from modules.banners import banners
import os

def main():
    zgpriv = ZGPRIV()
    zgpriv.analyzer_zgpriv()
    
if __name__ == "__main__":
    banners()
    main()