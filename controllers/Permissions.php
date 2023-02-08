<?php namespace Gviabcua\UserPermissions\Controllers;

use BackendMenu;
use Winter\User\Models\User as UserModel;
use Winter\User\Models\UserGroup as UserGroupModel;

class Permissions extends \Backend\Classes\Controller
{
    public $requiredPermissions = [
        'gviabcua.userpermissions.access_permissions'
    ];

    public $implement = [
        'Backend.Behaviors.FormController',
        'Backend.Behaviors.ListController',
    ];

    public $formConfig = 'form_config.yaml';

    public $listConfig = 'list_config.yaml';

    public function __construct()
    {
        parent::__construct();
        BackendMenu::setContext('Winter.User', 'user', 'permissions');
        $this->addCss('/plugins/gviabcua/userpermissions/assets/css/form.css');
    }
}
