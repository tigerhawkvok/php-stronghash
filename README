PHP-STRONGHASH

Cross-Site Hasher. Will always return most secure hash possible.	

/*************

USE:	

Add the following code to your document before calling the function:

  require_once('PATH/TO/FILE/php-stronghash.php');

Then, simply call 

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

************/

This package includes a couple of dependency functions. Of primarily
utility are:

  genUnique([LENGTH=128, RETURN_BASE_16=TRUE]) : generates a unique string. Length defaults to 128. 
                                                 This uses PHP's rand(), the current URL, computer time, 
                                                 and a true random value from random.org. If the RETURN_BASE_16 
                                                 flag is set, it will return a SHA-512 hash of the seed value. 
                                                 Otherwise, just the unique seed is returned, which may be 
                                                 shorter than the requested length.

  createSalt([LENGTH=32,ADDITIONAL_ENTROPY=NULL]) : Generate a salt of length LENGTH using PHP's rand(), 
                                                    the current URL, and the computer time. This is faster than
                                                    genUnique().
