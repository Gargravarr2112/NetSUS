<?php
session_start();
include "inc/config.php";
include "inc/functions.php";
$amAuthURL="dashboard.php";
if (isset($_SESSION['isAuthUser'])) {
	header('Location: '. $amAuthURL);
}

$isAuth=FALSE;

$type="suslogin";

if ((isset($_POST['username'])) && (isset($_POST['password']))) {
	$username = $_POST['username'];
	$_SESSION['username'] = $username;

	if ($_POST['loginwith'] == 'suslogin') {
		$password = hash("sha256", $_POST['password']);
		if (($username != "") && ($password != "")) {
			if ($username == $admin_username && $password == $admin_password) {
				$isAuth = TRUE;
			} else {
				$loginerror = "NetSUS: Invalid Credentials";
			}
		}
	}

	if (($_POST['loginwith'] == 'adlogin') || ($_POST['loginwith'] == 'ldaplogin')) {

		define(LDAP_OPT_DIAGNOSTIC_MESSAGE, 0x0032);
		$type=$_POST['loginwith'];

		$ldapconn = ldap_connect($conf->getSetting("ldapserver"));
		if ($ldapconn)
		{
			ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
			ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);

			if ($conf->getSetting("ldapbinddn") != "")
			{
				if (!ldap_bind($ldapconn, $conf->getSetting("ldapbinddn"), $conf->getSetting("ldapbindpw")))
				{
					$loginerror = "Unable to authenticate to LDAP with bind user";
				}
			}

			$basedn = "dc=" . implode(",dc=", explode(".", $conf->getSetting("ldapdomain")));
			$adLogin = false;
			if ($type == 'adlogin')
			{
				$username = $username . "@" . $conf->getSetting("ldapdomain");
				$commonName = "(|(samaccountname=$username)(userprincipalname=$username))";
				$adLogin = true;
				$userDN = getDN($ldapconn, $commonName, $basedn, $debug);
			}
			else
			{
				$bindOU = $conf->getSetting("ldapbindou");
				if ($bindOU != "")
					$bindOU = ",ou=" . $bindOU;
				$userDN = "uid=" . $username . $bindOU . "," . $basedn;
				if ($debug) print("\nUser DN:" . $userDN);
			}
			if (ldap_bind($ldapconn, $userDN, $_POST['password']))
			{
				if ($debug) print("\nBind succeeded for user: " . $userDN);
				$groupOU = $conf->getSetting("ldapgroupou");
				if ($groupOU != "")
					$groupOU = 'ou=' . $groupOU . ',';

				foreach ($conf->getAdmins() as $key => $value)
				{
					if ($debug) print("\nChecking user membership in group " . $value['cn']);
					$groupdn = getDN($ldapconn, 'cn='.$value['cn'], $groupOU.$basedn, $debug);
					if ($debug) print("\nGroup DN: " . $groupdn);
					if (checkLDAPGroupEx($ldapconn, $userDN, $groupdn, $adLogin, $debug))
					{
						$isAuth = TRUE;
					}
				}
				ldap_unbind($ldapconn);
			}
			else if (ldap_get_option($ldapconn, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_error))
			{
				$loginerror = "LDAP: Error on Bind - ".$extended_error;
			}
			else
			{
				$loginerror = "LDAP: Invalid Credentials for $username";
			}
		}
		else
		{
			$loginerror = "LDAP: Unable to Connect to URL";
		}
	}
}

if ($isAuth) {
	$_SESSION['isAuthUser'] = 1;
	$sURL = "dashboard.php";
	if ($debug) {
		print $sURL . "<br>";
		print $_SESSION['isAuthUser'];
	}
	if (!($debug)) {
		header('Location: '. $sURL);
	}
}
elseif ($conf->getSetting("webadmingui") == "Disabled") {
?>

<!DOCTYPE html>

<html>
	<head> 
	    <title>NetBoot/SUS/LDAP Proxy Server</title>
	    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
	    <meta http-equiv="expires" content="0">
	    <meta http-equiv="pragma" content="no-cache">
		<link href="theme/bootstrap.css" rel="stylesheet" media="all">
		<link rel="stylesheet" href="theme/styles.css" type="text/css">
	</head> 

	<body>
		<div class="col-xs-12 col-sm-8 col-md-6 col-lg-5 col-centered">
			<div class="panel panel-default panel-login">
				<div class="panel-heading">
					<div class="panel-title text-center"><img src="images/NSUS-logo.png" height="65"></div>
				</div>
				<div class="panel-body">
					<div class="alert alert-danger">WebAdmin GUI is disabled</div>
				</div>
			</div>
		</div>
	</body>
</html>

<?php
} else {
?>

<!DOCTYPE html>

<html>
	<head>
		<title>NetBoot/SUS/LDAP Proxy Server Login</title>
		<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
		<meta http-equiv="expires" content="0">
		<meta http-equiv="pragma" content="no-cache">
		<link href="theme/bootstrap.css" rel="stylesheet" media="all">
		<link rel="stylesheet" href="theme/styles.css" type="text/css">
		<script type="text/javascript" src="scripts/jquery/jquery-2.2.0.js"></script>
		<script type="text/javascript" src="scripts/bootstrap.min.js"></script>
	</head> 

	<body>
<!--	<div class="col-xs-12 col-sm-8 col-sm-offset-2 col-md-6 col-md-offset-3 col-lg-5 col-lg-offset-3">-->
		<div class="col-xs-12 col-sm-8 col-md-6 col-lg-5 col-centered">
			<div class="panel panel-default panel-login">

				<div class="panel-heading">
					<div class="panel-title text-center"><img src="images/NSUS-logo.png" height="55"></div>
				</div>

				<div class="panel-body">

					<?php if(isset($loginerror)) {
						echo "<div class=\"alert alert-danger\">".$loginerror."</div>";
					} ?>

					<form name="loginForm" class="form-horizontal" id="login-form" method="post" action="">
						<legend>Login with</legend>
						<div class="radio radio-inline radio-primary">
							<input type="radio" id="suslogin" name="loginwith" value="suslogin" <?php echo ($type=="suslogin"?" checked=\"checked\"":"") ?>>
							<label for="suslogin">Local Account</label>
						</div>
						<div class="radio radio-inline radio-primary">
							<input type="radio" id="ldaplogin" name="loginwith" value="ldaplogin" <?php echo ($type=="ldaplogin"?" checked=\"checked\"":"") ?>>
							<label for="ldaplogin">LDAP Directory</label>
						</div>
						<div class="radio radio-inline radio-primary">
							<input type="radio" id="adlogin" name="loginwith" value="adlogin" <?php echo ($type=="adlogin"?" checked=\"checked\"":"") ?>>
							<label for="adlogin">Active Directory</label>
						</div>
						<div class="username"><input id="username" type="text" class="form-control input-sm" name="username" value="" placeholder="Username"></div>
						<div class="password"><input id="password" type="password" class="form-control input-sm" name="password" placeholder="Password"></div>
						<div><input type="submit" class="btn btn-primary pull-right" name="submit" value="Log In"></div>
					</form>
				</div>
			</div>
		</div>
	</body>
</html>
<?php
}
?>
