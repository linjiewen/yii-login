<?php

namespace yiiComponent\yiiLogin\models;

use Yii;

/**
 * 基础速率限制活跃记录类
 */
class BaseRateLimitActiveRecord extends BaseIdentityActiveRecord
{
    /**
     * 返回允许的请求的最大数目及时间
     *
     * @param  \yii\web\Request $request
     * @param  \yii\base\Action $action
     * @return array
     */
    public function getRateLimit($request, $action)
    {
        return Yii::$app->params['rateLimit'];
    }

    /**
     * 返回剩余的允许的请求和最后一次速率限制检查时 相应的 UNIX 时间戳数
     *
     * @param  \yii\web\Request $request
     * @param  \yii\base\Action $action
     * @return array
     */
    public function loadAllowance($request, $action)
    {
        return [$this->allowance, $this->allowance_updated_at];
    }

    /**
     * 保存剩余的允许请求数和当前的 UNIX 时间戳
     *
     * @param \yii\web\Request $request
     * @param \yii\base\Action $action
     * @param int $allowance
     * @param int $timestamp
     */
    public function saveAllowance($request, $action, $allowance, $timestamp)
    {
        $this->allowance = $allowance;
        $this->allowance_updated_at = $timestamp;
        $this->save();
    }
}
