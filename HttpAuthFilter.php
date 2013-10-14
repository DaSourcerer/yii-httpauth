<?php
/* Copyright 2013 Da:Sourcerer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * HttpAuthFilter class
 *
 * @author Da:Sourcerer
 * @version 1.0
 * @license http://www.apache.org/licenses/LICENSE-2.0 ASL 2.0
 */
class HttpAuthFilter extends CFilter
{
	public $authModel='LoginForm';
	public $realm;

	public function preFilter($filterChain)
	{
		if(!Yii::app()->user->isGuest)
			return true;

		if(!array_key_exists('PHP_AUTH_USER', $_SERVER))
			$this->sendAuthHeaders();

		$model=new $this->authModel;
		$model->username=$_SERVER['PHP_AUTH_USER'];
		$model->password=$_SERVER['PHP_AUTH_PW'];

		if(!$model->login())
			$this->sendAuthHeaders();

		return true;
	}

	protected function sendAuthHeaders()
	{
		if($this->realm===null)
			$this->realm=Yii::app()->name;
		$this->realm=addcslashes($this->realm, '"\\');
		header(sprintf('WWW-Authenticate: Basic realm="%s"', $this->realm));
		throw new CHttpException(401);
	}
}