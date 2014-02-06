<?php
// (c) Copyright 2002-2013 by authors of the Tiki Wiki CMS Groupware Project
// 
// All Rights Reserved. See copyright.txt for details and a complete list of authors.
// Licensed under the GNU LESSER GENERAL PUBLIC LICENSE. See license.txt for details.
// $Id: Expr.php 44444 2013-01-05 21:24:24Z changi67 $

class TikiDb_Expr
{
	private $string;
	private $arguments;

	function __construct($string, array $arguments)
	{
		$this->string = $string;
		$this->arguments = $arguments;
	}

	function getQueryPart($currentField)
	{
		return str_replace('$$', $currentField, $this->string);
	}

	function getValues()
	{
		return $this->arguments;
	}
}
