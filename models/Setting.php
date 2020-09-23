<?php

namespace yiiComponent\yiiLogin\models;

use Yii;

/**
 * This is the model class for table "{{%setting}}".
 *
 * @property string $id
 * @property string $name 名称
 * @property string $title 标题
 * @property string $value 值（json）
 * @property int $is_trash 是否删除，0=>否，1=>是
 * @property int $status 状态，0=>禁用，1=>启用
 * @property string $created_at 创建时间
 * @property string $updated_at 更新时间
 * @property string $deleted_at 删除时间
 */
class Setting extends \yiiComponent\yiiLogin\models\BaseActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return '{{%setting}}';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['id', 'is_trash', 'status'], 'integer', 'min' => 0],
            [['value'], 'required'],
            [['value'], 'string'],
            [['name'], 'string', 'max' => 64],
            [['title'], 'string', 'max' => 128],

            [['created_at', 'updated_at', 'deleted_at'], 'datetime', 'format' => 'yyyy-MM-dd HH:mm:ss'],

            [['name', 'title', 'value'], 'default', 'value' => ''],
            [['is_trash'], 'default', 'value' => 0],
            [['status'], 'default', 'value' => 1],
            [['deleted_at'], 'default', 'value' => null],

            [['name'], 'unique'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'id' => Yii::t('app', 'ID'),
            'name' => Yii::t('app', '名称'),
            'title' => Yii::t('app', '标题'),
            'value' => Yii::t('app', '值（json）'),
            'is_trash' => Yii::t('app', '是否删除，0=>否，1=>是'),
            'status' => Yii::t('app', '状态，0=>禁用，1=>启用'),
            'created_at' => Yii::t('app', '创建时间'),
            'updated_at' => Yii::t('app', '更新时间'),
            'deleted_at' => Yii::t('app', '删除时间'),
        ];
    }
}
