<?php
/*

  Cross-Site Hasher. Will always return most secure hash possible.
  USE:
  Simply call 
    hasher(YOUR_DATA[,SALT=null,ALGORITHM=null,BOOL create_salt_if_not_supplied=true,ROUNDS=100000])
  which returns an array of the form:
    Array {
            [hash] => HASH_STRING,
	    [salt] => USED_SALT,
	    [algo] => ALGORITHM_USED
          }

  For convenience, when using crypt() this algorthm strips the data crypt() keeps for itself to make the hash easier to parse. 
  The unadulterated hash is then stored in the key [full_hash].
  When rounds are used other than the default, they are stored in the key [rounds].

  If you wish to verify a hash, calling:
    verifyHash(STORED_HASH,COMPARISON_DATA,[STORED_SALT,STORED_ALGORITHM,OVERRIDE_DEFAULT_ROUNDS_NUMBER])
  will return TRUE on a match, and FALSE on a failure. It uses a slow match to avoid attacks on speed matching.
  If the function is unable to use the same algorithm, it will return FALSE. It is highly recommended to always specify the algo.
  If COMPARISON_DATA is the original array passed from hasher(), the correct data is always passed automatically.

Velociraptor Systems Software / www.velociraptorsystems.com
Copyright (C) 2013 Philip Kahn

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301  USA

http://opensource.org/licenses/LGPL-3.0

 */

$default_rounds=10000;

function hasher($data,$salt=null,$use=null,$forcesalt=true,$rounds=null)
{
  //hashes with most secure algorithm and returns the hash used
  global $default_rounds;
  $rounds= preg_match("/^([0-9]+)$/",$rounds) ? $default_rounds:$rounds;
  $userset = empty($use) ? false: true;
  $cryptgo=false;
  $use_crypt= strpos($use,"crypt")!==false ? true:false;
  $use_pbkdf2= strpos($use,"pbkdf2")!==false ? true:false;
  $simplerounds = strpos($use,"-multi")!==false ? true:false;
  $nonnative= strpos($use,"-nn")!==false ? true:false;
  if($salt==null && $forcesalt===true) $salt=genUnique();
  if(function_exists('hash'))
    {
      // All more advanced algos also mean that hash() can be used
      $list=hash_algos();
      if(empty($use))
	{
	  // manually iterate through common inclusions and prefer in order
	  foreach($list as $algo)
	    {
	      if($algo=='sha512')
		{
		  $use=$algo;
		  break;
		}
	      if($algo=='sha384')
		{
		  $use=$algo;
		}
	      if($algo=='sha256')
		{
		  if($use!='sha384') $use=$algo;
		}
	      if($algo=='sha224')
		{
		  if($use!='sha384' && $use!='sha256') $use=$algo;
		}
	    }
	}
      if(!empty($use))
	{
	  if(!empty($salt)) 
	    {
	      if($use_crypt) $use=str_replace("crypt","",$use);
	      if($use_pbkdf2) $use=str_replace("pbkdf2","",$use);
	      // test crypt() usability
	      if((CRYPT_SHA512==1 && $use=='sha512') || (CRYPT_SHA256==1 && $use=='sha256')) $cryptgo=true;
	      else if(CRYPT_BLOWFISH==1) 
		{
		  $cryptgo=true;
		  $use='blowfish';
		}
	      else if($use_crypt) return array(false,"Crypt was required but the requested algorithm $use isn't available");
	      
	      // run PBKDF2 if present
	      if(function_exists('hash_pbkdf2') && !$use_crypt && !$nonnative) return array("hash"=>hash_pbkdf2($use,$data,$salt,$rounds),"salt"=>$salt,"algo"=>$use."pbkdf2","rounds"=>$rounds);
	      else if(function_exists('crypt') && ($use_crypt || !$userset) && $cryptgo)
		{
		  $data=urlencode($data);
		  switch($use)
		    {
		      case "sha512":
			$salt=substr($salt,0,16);
		        $ss="\$6\$rounds=$rounds\$".$salt."\$";
		        break;
		      case "sha256":
			$salt=substr($salt,0,16);
			$ss="\$5\$rounds=$rounds\$".$salt."\$";
			break;
		      case "blowfish":
			$salt=substr(sha1($salt),0,22);
			$ss="\$2a\$07\$".$salt."\$";
			break;
		      default:
			$ss=false;
		    }
		  if($ss!==false)
		    {
		      // do crypt
		      $result=crypt($data,$ss);
		      $result_small=explode("\$",$result);
		      $size=sizeof($result_small);
		      $result_small=$result_small[$size-1]; // trim the extra data in case the user wants an unadulterated hash.
		      return array('hash'=>$result_small,"full_hash"=>$result,"salt"=>$salt,"algo"=>$use."crypt","rounds"=>$rounds,"string"=>$ss);
		    } // End crypt cases. Now all sophisticated algorithms supported by the system have been exhausted. Use basic hasher.
		  else 
		    {
		      // if this block was executed at the user request, only crypt() should have run.
		      if($userset) return array(false,"Unable to use $use in crypt().");
		      try
			{
			  // try non-native implmentation of pbkdf2
			  $hash=pbkdf2($use,$data,$salt,$rounds,128);
			  return array('hash'=>$hash,"salt"=>$salt,"algo"=>$use."pbkdf2-nn","rounds"=>$rounds);
			}
		      catch(Exception $e)
			{
			  if(function_exists('hash_hmac') && strpos($use,"hmac")!==false) return array('hash'=>hash_hmac($use,$salt.$data,$salt),"salt"=>$salt,"algo"=>$use."_hmac");
			  else if(!function_exists('hash_hmac') && strpos($use,"hmac")!==false) return false;
			}
		      $string=$salt.$data;
		      for($i=0;$i<$rounds;$i++)
			{
			  // a very very basic multi-round hash
			  $string=hash($use,sha1($string).$string);
			}
		      return array('hash'=>$string,"salt"=>$salt,"algo"=>$use."-multi","rounds"=>$rounds);
		    }
		} // End using crypt
	      else if(!function_exists('crypt') && $use_crypt) return false;
	      else if((!function_exists('hash_pbkdf2') && ($use_pbkdf2 || !$userset)) || ($use_pbkdf2 && $nonnative)) 
		{
		  try
		    {
		      // try non-native implmentation of pbkdf2
		      $hash=pbkdf2($use,$data,$salt,$rounds,128);
		      return array('hash'=>$hash,"salt"=>$salt,"algo"=>$use."pbkdf2-nn","rounds"=>$rounds);
		    }
		  catch(Exception $e)
		    {
		      if($use_pbkdf2) return false; 
		    }
		}
	      else if(strpos($use,"pbkdf2-nn")!==false)
		{
		  $hash=pbkdf2(str_replace("pbkdf2-nn","",$use),$data,$salt,$rounds,128);
		  return array('hash'=>$hash,"salt"=>$salt,"algo"=>$use,"rounds"=>$rounds);
		}
	      // we've walked through all instances of crypt and pbkdf2 by now
	      if(function_exists('hash_hmac') && !$simplerounds)
		{ 
		  if($userset && strpos($use,"_hmac")!==false) return array('hash'=>hash_hmac(str_replace("hmac","",$use),$salt.$data,$salt),"salt"=>$salt,"algo"=>$use);
		  if(!$userset) return array('hash'=>hash_hmac($use,$salt.$data,$salt),"salt"=>$salt,"algo"=>$use."hmac");
		}
	      else if(!function_exists('hash_hmac') && strpos($use,"hmac")!==false && $userset) return false;
	      else if($simplerounds) // implies user set
		{
		  $string=$salt.$data;
		  for($i=0;$i<$rounds;$i++)
		    {
		      // a very very basic multi-round hash
		      $string=hash($use,sha1($string).$string);
		    }
		  return array('hash'=>$string,"salt"=>$salt,"algo"=>$use."-multi","rounds"=>$rounds);
		}
	      else return array('hash'=>hash($use,$salt.$data),"salt"=>$salt,"algo"=>$use);
	    } // End salt-requring functions
	  else return array('hash'=>hash($use,$salt.$data),"salt"=>$salt,"algo"=>$use);
	} // End search for supported hash algos
      else return array('hash'=>sha1($salt.$data),"salt"=>$salt,"algo"=>'sha1');
    } // End hash() supported
  return array('hash'=>sha1($salt.$data),"salt"=>$salt,"algo"=>'sha1');

}

function genUnique($len=128,$hash=true;)
{
  /*
    // Very slow unique string generator. 
    // Uses PHP rand(), computer time, current URL, best sha hash, and a true random value from random.org
   */
  $id1=createSalt();
  $id2=microtime_float();
  $id3=rand(0,10000000000);
  $id4_1=createSalt(64);
  $id4_2=$_SERVER['request_uri'];
  $id4_3=microtime_float();
  $id4_4=$id4_1.$id4_2.$id4;
  $id4=sha1($id4_4.createSalt(128));
  // random.org input
  $rurl='http://www.random.org/strings/?num=1&len=20&digits=on&upperalpha=on&loweralpha=on&format=plain&rnd=new';
  $string=@file_get_contents($rurl);
  $seed=$string.$id1.$id2.$id3.$id4;
  if($hash)
    {
      $hash=hash('sha512',$seed);
      return substr($hash,0,$len);
    }
  else return substr($seed,0,$len);
}

function createSalt($length=32,$add_entropy=null)
{
  $id1=uniqid(mt_rand(),true);
  $id2=md5(date('dDjlSwzWFmMntLYayABgGhiHsOZ'));
  $id3=crc32(curPageURL());
  $charset="!@#~`%^&*()-_+={}|[]:;'<>?,./";
  $repeats=rand(0,64);
  $i=0;
  $csl=strlen($charset);
  while($i<$repeats)
    {
      $pos=rand(0,$csl-1);
      $id4=substr($charset,$pos,1);
      $i++;
    }
  $salt=sha1($id2 . $id1 . $id3 . $id4 . $add_entropy); // add extra entropy if provided.
  $len=strlen($salt);
  if($length>$len) $length=$len;
  $diff=strlen($salt)-$length;
  $offset=rand(0,$diff);
  return substr($salt,$offset,$length);
}

function microtime_float()
{
    list($usec, $sec) = explode(" ", microtime());
    return ((float)$usec + (float)$sec);
}

function curPageURL() {
 $pageURL = 'http';
 if ($_SERVER["HTTPS"] == "on") {$pageURL .= "s";}
 $pageURL .= "://";
 if ($_SERVER["SERVER_PORT"] != "80") {
  $pageURL .= $_SERVER["SERVER_NAME"].":".$_SERVER["SERVER_PORT"].$_SERVER["REQUEST_URI"];
 } else {
  $pageURL .= $_SERVER["SERVER_NAME"].$_SERVER["REQUEST_URI"];
 }
 return $pageURL;
}

function verifyHash($hash,$orig_data,$orig_salt=null,$orig_algo=null,$orig_rounds=null)
{
  if(is_array($orig_data))
    {
      global $default_rounds;
      $orig_salt=$orig_data['salt'];
      $orig_algo=$orig_data['algo'];
      $orig_rounds= preg_match("/^([0-9]+)$/",$orig_data['rounds']) ? orig_data['rounds']:$default_rounds;
    }
  $newhash=hasher($orig_data,$orig_salt,$orig_algo,false,$orig_rounds);
  if($newhash[0]!==false) return slow_equals($hash,$newhash['hash']);
  else return false;
}


?>
<?php
/*
 * Password hashing with PBKDF2.
 * Author: havoc AT defuse.ca
 * www: https://defuse.ca/php-pbkdf2.htm
 */

// These constants may be changed without breaking existing hashes.
define("PBKDF2_HASH_ALGORITHM", "sha256");
define("PBKDF2_ITERATIONS", 1000);
define("PBKDF2_SALT_BYTES", 24);
define("PBKDF2_HASH_BYTES", 24);

define("HASH_SECTIONS", 4);
define("HASH_ALGORITHM_INDEX", 0);
define("HASH_ITERATION_INDEX", 1);
define("HASH_SALT_INDEX", 2);
define("HASH_PBKDF2_INDEX", 3);


// Compares two strings $a and $b in length-constant time.
function slow_equals($a, $b)
{
    $diff = strlen($a) ^ strlen($b);
    for($i = 0; $i < strlen($a) && $i < strlen($b); $i++)
    {
        $diff |= ord($a[$i]) ^ ord($b[$i]);
    }
    return $diff === 0; 
}

/*
 * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
 * $algorithm - The hash algorithm to use. Recommended: SHA256
 * $password - The password.
 * $salt - A salt that is unique to the password.
 * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
 * $key_length - The length of the derived key in bytes.
 * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
 * Returns: A $key_length-byte key derived from the password and salt.
 *
 * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
 *
 * This implementation of PBKDF2 was originally created by https://defuse.ca
 * With improvements by http://www.variations-of-shadow.com
 */
function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
{
    $algorithm = strtolower($algorithm);
    if(!in_array($algorithm, hash_algos(), true))
        die('PBKDF2 ERROR: Invalid hash algorithm.');
    if($count <= 0 || $key_length <= 0)
        die('PBKDF2 ERROR: Invalid parameters.');

    $hash_length = strlen(hash($algorithm, "", true));
    $block_count = ceil($key_length / $hash_length);

    $output = "";
    for($i = 1; $i <= $block_count; $i++) {
        // $i encoded as 4 bytes, big endian.
        $last = $salt . pack("N", $i);
        // first iteration
        $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
        // perform the other $count - 1 iterations
        for ($j = 1; $j < $count; $j++) {
            $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
        }
        $output .= $xorsum;
    }

    if($raw_output)
        return substr($output, 0, $key_length);
    else
        return bin2hex(substr($output, 0, $key_length));
}
?>