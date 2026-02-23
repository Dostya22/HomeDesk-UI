using System.Windows;
using System.Windows.Media;
using HomeDesk_UI.Services;

namespace HomeDesk_UI;

/// <summary>
///     Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private readonly AuthService _authService = new();

    public MainWindow()
    {
        InitializeComponent();
    }

    private async void SignUpButton_OnClick(object sender, RoutedEventArgs e)
    {
        var name = NameText.Text?.Trim() ?? string.Empty;
        var email = EmailText.Text?.Trim() ?? string.Empty;
        var password = PasswordBox.Password ?? string.Empty;
        var invite = InviteText.Text?.Trim() ?? string.Empty;

        // basic validation
        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(email) ||
            string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(invite))
        {
            StatusText.Text = "Please fill in all fields.";
            StatusText.Foreground = Brushes.Orange;
            return;
        }

        SignUpButton.IsEnabled = false;
        Progress.Visibility = Visibility.Visible;
        StatusText.Text = "Signing you up...";
        StatusText.Foreground = Brushes.LightBlue;

        try
        {
            await _authService.RegisterAsync(email, name, password, invite);
            StatusText.Text = "Success! Your account has been created.";
            StatusText.Foreground = Brushes.LightGreen;
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Sign up failed: {ex.Message}";
            StatusText.Foreground = Brushes.IndianRed;
        }
        finally
        {
            Progress.Visibility = Visibility.Collapsed;
            SignUpButton.IsEnabled = true;
        }
    }
}