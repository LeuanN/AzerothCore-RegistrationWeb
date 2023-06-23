<?php show_source(__FILE__);
// MySQL connection data
$dbhost = "IP_FOR_YOUR_DATABASE";
$dbuser = "USER_FOR_DATABASE (Default: root)";
$dbpass = "PASSWORD_FOR_YOUR_DATABASE";
$dbname = "acore_auth (This is the default by azerothcore)";

// Function to calculate the verifier
function CalculateSRP6Verifier($username, $password, $salt)
{
    // Constant algorithm values
    $g = gmp_init(7);
    $N = gmp_init('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);

    // Calculate first hash
    $h1 = sha1(strtoupper($username . ':' . $password), TRUE);

    // Calculate second hash
    $h2 = sha1($salt.$h1, TRUE);

    // Convert to integer (little endian)
    $h2 = gmp_import($h2, 1, GMP_LSW_FIRST);

    // g^h2 mod N
    $verifier = gmp_powm($g, $h2, $N);

    // Convert back to byte array (little endian)
    $verifier = gmp_export($verifier, 1, GMP_LSW_FIRST);

    // Pad with zeros up to 32 bytes, remember that zeros go at the end in little endian
    $verifier = str_pad($verifier, 32, chr(0), STR_PAD_RIGHT);

    // Done!
    return $verifier;
}

// Function to insert a new record into the database
function InsertAccount($username, $password, $email)
{
    global $dbhost, $dbuser, $dbpass, $dbname;

    // Generate a salt and calculate the verifier
    list($salt, $verifier) = GetSRP6RegistrationData($username, $password);

    // Establish connection to the database
    $conn = mysqli_connect($dbhost, $dbuser, $dbpass, $dbname);

    // Check the connection
    if (!$conn) {
        die("MySQL connection error: " . mysqli_connect_error());
    }

    // Escape values to prevent SQL injection
    $escapedUsername = mysqli_real_escape_string($conn, $username);
    $escapedSalt = mysqli_real_escape_string($conn, $salt);
    $escapedVerifier = mysqli_real_escape_string($conn, $verifier);
    $escapedEmail = mysqli_real_escape_string($conn, $email);

    // Create the SQL query
    $sql = "INSERT INTO account (username, salt, verifier, email) VALUES ('$escapedUsername', '$escapedSalt', '$escapedVerifier', '$escapedEmail')";

    // Execute the query
    if (mysqli_query($conn, $sql)) {
        echo "Registration successful. Data has been inserted into the database.";
    } else {
        echo "Error inserting data: " . mysqli_error($conn);
    }

    // Close the connection
    mysqli_close($conn);
}

// Get SRP6 registration data
function GetSRP6RegistrationData($username, $password)
{
    // Generate a random salt
    $salt = random_bytes(32);

    // Calculate the verifier using this salt
    $verifier = CalculateSRP6Verifier($username, $password, $salt);

    // Done! This is what gets stored in the accounts table.
    return array($salt, $verifier);
}

// Check if the form has been submitted
if (isset($_POST['submit'])) {
    // Get form values
    $username = $_POST['username'];
    $password = $_POST['password'];
    $email = $_POST['email'];

    // Insert the account into the database
    InsertAccount($username, $password, $email);
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Account Registration</title>
</head>
<body>
    <h2>Account Registration</h2>
    <form method="post" action="">
        <label for="username">Username:</label>
        <input type="text" name="username" required><br><br>
    <label for="password">Password:</label>
    <input type="password" name="password" required><br><br>

    <label for="email">Email:</label>
    <input type="email" name="email" required><br><br>

    <input type="submit" name="submit" value="Register">
</form>
</body>
</html>
