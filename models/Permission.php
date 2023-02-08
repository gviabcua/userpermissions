<?php namespace Gviabcua\UserPermissions\Models;

use Model;
use Winter\User\Models\User as UserModel;
use Winter\User\Models\UserGroup as UserGroupModel;

class Permission extends Model
{
    use \Winter\Storm\Database\Traits\Validation;
    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'user_userpermissions_permissions';

    /*
     * Validation
     */
    public $rules = [
        'name' => 'required',
    ];

    public $belongsToMany = [
        'users' => ['Winter\User\Models\User',
            'table' => 'user_userpermissions_user_permission',
            'key' => 'permission_id',
            'otherKey' => 'user_id',
            'timestamps' => true,
            'pivot' => ['permission_state'],
        ],
        'groups' => ['Winter\User\Models\UserGroup',
            'table' => 'user_userpermissions_group_permission',
            'key' => 'permission_id',
            'otherKey' => 'group_id',
            'timestamps' => true,
        ],
    ];

    public function beforeSave()
    {
        $this->setCodeIfEmpty();
        $this->sluggifyCode();
    }

    protected function setCodeIfEmpty()
    {
        if (empty($this->code)) {
            $this->code = str_slug($this->name, '-');
        }
    }

    protected function sluggifyCode()
    {
        $this->code = str_slug($this->code, '-');
    }

    public function afterCreate()
    {
        $this->addNewPermissionToUsers();
    }

    protected function addNewPermissionToUsers()
    {
        $users = UserModel::all();
        if($users) {
            foreach($users as $user) {
                $user->user_permissions()->attach($this->id, ['permission_state' => 2]);
            }
        }
    }
}
