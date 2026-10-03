from rich.console import Console
from rich.text import Text

console = Console()

BANNER = r"""
      /\         S I S I F O
     /  \        Offensive Security Framework
    /____\       
   /      \      
  /________\     
"""


def print_banner():
    console.print(Text(BANNER, style="bold amber"))
