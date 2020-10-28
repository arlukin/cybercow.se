#!/usr/local/bin/php -n
<?php
/*
 * Author: Daniel "Arlukin" Lindh (daniel cybercow se)
 * Web page: http://articles.cybercow.se/2009111561/articles/linux/find-free-domains.html
 *
 * Requirements:
 * http://sourceforge.net/projects/phpwhois/files/phpwhois/
 *
 * Copy and modify it as you like, but don't blame me if anything goes wrong =)
 */
include('phpwhois-4.1.3/whois.main.php');
DEFINE(NEWLINE, "\n");
DEFINE(VERSION, "0.1");

function add_pid($pid)
{
	static $pids = 0;
	$pids++;

	while ($pids > 200)
	{
		echo("_");
		pcntl_wait($status); //Protect against Zombie children
		$pids--;
	}
}

function make_database_connection()
{
	return new SQLiteDatabase('mysqlitedb');
}

function sqlite_is_no_error($query, $error)
{
	if (!$query)
	{
		exit("Error in query: '$error'");
	}
	else
	{
		return true;
	}
}

function create_database()
{
	$dbhandle = make_database_connection();
	$query = $dbhandle->queryExec("CREATE TABLE domains (domain STRING, exist bool, PRIMARY KEY(domain ASC))", $error);
	if (sqlite_is_no_error($query, $error))
	{
	    echo 'Number of rows modified: ', $dbhandle->changes() . NEWLINE;
	}
}

function list_domains($domain_, $exist_)
{
	$dbhandle = make_database_connection();
	$query = $dbhandle->query("select domain, exist from domains WHERE domain like '$domain_' AND exist = $exist_", SQLITE_NUM, $error);

	if (sqlite_is_no_error($query, $error))
	{
		print $query->numRows() . NEWLINE;
		while($row = $query->fetch())
		{
			echo($row[0] . ' - ' . $row[1] . NEWLINE);
		}
	}
}

function count_domains()
{
	$dbhandle = make_database_connection();
	$query = $dbhandle->query("select count(*) from domains", SQLITE_NUM, $error);

	if (sqlite_is_no_error($query, $error))
	{
		$row = $query->fetch();
		echo('Number of domains: ' . $row[0] . NEWLINE);
	}
}

function insert_domain($domain_, $exist_)
{
	$dbhandle = make_database_connection();
	$query = $dbhandle->queryExec("replace into domains (domain, exist) VALUES('$domain_', $exist_)", $error);
	sqlite_is_no_error($query, $error);
}

function exist_domain($domain_)
{
	$dbhandle = make_database_connection();
	$query = $dbhandle->query("select exist from domains WHERE domain = '$domain_'", SQLITE_NUM, $error);
	sqlite_is_no_error($query, $error);

	$row = $query->fetch();
	return $row[0];
}

function has_who_is_result($result)
{
	return (
			is_array($result) &&
			array_key_exists('regrinfo', $result) &&
			array_key_exists('registered', $result['regrinfo'])
		);
}

function who_is($domain_)
{
	$exist = NULL;
	$pid = pcntl_fork();
	if ($pid == -1)
	{
		die('could not fork');
	}
	else if (!$pid)
	{
		$whois = new Whois();
		$result = $whois->Lookup($domain_);
		if (!has_who_is_result($result))
		{
			sleep(60);
			$result = $whois->Lookup($domain_);
		}

		if (has_who_is_result($result))
		{
			if($result['regrinfo']['registered'] == 'yes')
			{
				$exist = 1;
			}
			else
			{
				$exist = 0;
			}

			insert_domain($domain_, $exist);
		}
		else
		{
			echo('E');
		}
		exit;
	}
	else
	{
		add_pid($pid);
	}
}


function retrive_domains($prefix_, $suffix_, $level_, $in_ = '')
{
	if ($level_ == 0)
	{
		$domain = $prefix_.  $in_ . $suffix_;
		$exist = exist_domain($domain);
		if ( $exist === NULL)
		{
			echo('.');
			$exist = who_is($domain);
		}

		if ($show_result_)
		{
			echo $domain . ' - ' . $exist. NEWLINE;
		}
		return;
	}
	$level_--;

	for($a=97;$a<123;$a++)
	{
		retrive_domains($prefix_, $suffix_, $level_, $in_ . chr($a));
	}
}

function scan_free_domains($num_of_characters_, $prefix_, $suffix_, $show_result_)
{
	for ($i=1;$i<$num_of_characters_;$i++)
	{
		retrive_domains($prefix_, $suffix_, $i);
	}
	echo "wait" . NEWLINE;
	pcntl_wait($status); //Protect against Zombie children
	if ($show_result_)
	{
		list_domains($prefix_ . '%' . $suffix_, '0');
	}
}

function write_help()
{
	echo('freedomain version ' . VERSION . ' by cybercow.se' . NEWLINE);
	echo('freedomain 1' . NEWLINE);
	echo('  Create the SQLite database, need to be executed first.' . NEWLINE);

	echo('freedomain 2 3 a .com 1' . NEWLINE);
	echo('  Scan for new free domains.' . NEWLINE);
	echo('  arg 1 is number of characters in the domain.' . NEWLINE);
	echo('  arg 2 domain prefix.' . NEWLINE);
	echo('  arg 3 domain suffix.' . NEWLINE);
	echo('  arg 4 1=show the result.' . NEWLINE);

	echo('freedomain 3' . NEWLINE);
	echo('  Count number of scanned domains' . NEWLINE);

	echo('freedomain 4 an%.com 0' . NEWLINE);
	echo('  Will list all scanned domains in the database' . NEWLINE);
	echo('  arg 1 the domains to list, SQL like statement.' . NEWLINE);
	echo('  arg 2 0=all available domains, 1 = all existing domains.' . NEWLINE);

	die(1);
}

function main($argc, $argv)
{
	if ($argc < 2 || $argc > 6)
	{
		write_help();
	}

	switch($argv[1])
	{
		case 1:
		create_database();
		break;

		case 2:
		scan_free_domains($argv[2], $argv[3], $argv[4], $argv[5]);
		break;

		case 3:
		count_domains();
		break;

		case 4:
		list_domains($argv[2], $argv[3]);
		break;
	}
}

main($argc, $argv);
?>
