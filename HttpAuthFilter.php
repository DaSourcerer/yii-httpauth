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
 * This filter implements http basic authentication for controller actions. This does not affect users who are already
 * logged in through regular means.
 *
 * @author Da:Sourcerer <webmaster@dasourcerer.net>
 * @version 1.0
 * @license http://www.apache.org/licenses/LICENSE-2.0 ASL 2.0
 */
class HttpAuthFilter extends CFilter
{
	/**
	 * The model handling authentication
	 *
	 * In a new, bootstrapped Yii application, this will be 'LoginModel' (which also happens to be the default).
	 * @var string
	 */
	public $authModel='LoginForm';

	/**
	 * The login model's attribute carrying the username
	 * @var string
	 */
	public $usernameAttribute='username';

	/**
	 * The login model's attribute carrying the password
	 * @var string
	 */
	public $passwordAttribute='password';

	/**
	 * The 'realm' advertised to the http client
	 *
	 * This can be some descriptive text regarding the resource you are trying to protect. If set to <kbd>null</kbd>,
	 * the value of Yii::app()->name will be taken. Please see to it that no characters outside iso-8859-1 make it here
	 * as this could seriously cripple http responses. Also note that this value will be turned into a quoted string
	 * which mandates the escaping of double-quotes (") and backslashes (\). This seems to cause problems with some
	 * browsers like <a href="https://bugzilla.mozilla.org/show_bug.cgi?id=676358">Firefox</a>.
	 * @var string|null
	 */
	public $realm;

	public function preFilter($filterChain)
	{
		if(!Yii::app()->user->isGuest)
			return true;

		if(!array_key_exists('PHP_AUTH_USER', $_SERVER))
			$this->sendAuthHeaders();

		$model=new $this->authModel;
		$model->{$this->usernameAttribute}=$_SERVER['PHP_AUTH_USER'];
		$model->{$this->passwordAttribute}=$_SERVER['PHP_AUTH_PW'];

		if(!$model->login())
			$this->sendAuthHeaders();

		return true;
	}

	/**
	 * Send out the headers demanding authentication by the client among a 401 (unauthorized) status code.
	 * @throws CHttpException
	 */
	protected function sendAuthHeaders()
	{
		if($this->realm===null)
			$this->realm=Yii::app()->name;
		$this->realm=addcslashes($this->realm, '"\\');
		header(sprintf('WWW-Authenticate: Basic realm="%s"', $this->realm));
		throw new CHttpException(401);
	}
}