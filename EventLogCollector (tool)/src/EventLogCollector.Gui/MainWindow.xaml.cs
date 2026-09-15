using System.Windows;
using EventLogCollector.Gui.ViewModels;

namespace EventLogCollector.Gui;

// main window logic
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel();
    }
}
