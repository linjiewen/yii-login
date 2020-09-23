<?php

use yiiComponent\yiiLogin\LoginForm;
use yiiComponent\yiiLogin\UserCreateForm;
use yiiComponent\yiiLogin\UserOauthForm;
use yiiComponent\yiiLogin\models\User;
use yii\web\HttpException;

/**
 * Class Test
 */
class Test extends \yii\rest\Controller
{
    /**
     * 登录
     *
     * @param  string [$uniqid = ''] 唯一字符用于确认用户（预留）
     * @return LoginForm|UserCreateForm|array
     * @throws HttpException
     * @throws \Throwable
     */
    public function actionLogin($uniqid = '')
    {
        $data = Yii::$app->request->post();

        // 判断是否第三方登录
        if (isset($data['identity']) && !empty($data['identity'])) {
            $model = new LoginForm(['scenario' => 'third-party']);
        } else {
            $model = new LoginForm(['scenario' => 'user']);
        }

        $model->modelClass = User::className();
        $model->load($data, '');
        //注意：
        //1.$modelUser 该命名建议不要修改，返回的是User对象或者错误提示数组。
        //2.不要改为$model，会导致赋值给LoginForm里面的数据拿不到。
        $modelUser = $model->submit();

        if (!is_array($modelUser)) {
            //判断是否第三方登录，需要用到LoginForm里面的数据
            if ($model->scenario == 'third-party') {
                $userOauth = $modelUser
                    ->getUserOauths()
                    ->where(['type' => $model->type, 'identity' => $model->identity])
                    ->limit(1)
                    ->one();

                if ($userOauth) {
                    throw new HttpException(401, Yii::t('app/error', '该手机号码已经绑定过微信号。'));
                } else {
                    // 授权绑定手机号操作，需要用到LoginForm里面的updateUserMess()方法
                    $model->updateUserMess($modelUser);
                }
            }

            return $modelUser;
        } else if (isset($modelUser['mobile'][0]) && $modelUser['mobile'][0] == '当前手机号未注册。') {
            // 第三方注册
            if ($model->scenario == 'third-party') {
                $model = new UserCreateForm(['scenario' => 'third-party']);
                // 自动注册
            } else {
                $model = new UserCreateForm(['scenario' => 'user']);
                $model->invite = $data['invite'];
                $model->activityId = $data['activityId'];
                $model->activityMissionId = $data['activityMissionId'];
            }

            $model->modelClass = User::className();
            $model->load(Yii::$app->request->post(), '');
            $modelUser = $model->submit();

            if (!is_array($modelUser)) {
                return $modelUser;
            }
        }

        throw new HttpException(401, json_encode($modelUser));
    }

    /**
     * 授权登录
     *
     * @return UserOauthForm|array|mixed
     * @throws HttpException
     * @throws \Throwable
     */
    public function actionOauthLogin()
    {
        $model = new UserOauthForm;
        $model->load(Yii::$app->request->post(), '');
        $model = $model->submit();

        if (!is_array($model)) {
            return $model;
        } else {
            throw new HttpException(422, json_encode($model));
        }
    }

    /**
     * 登出
     *
     * @throws HttpException
     */
    public function actionLogout()
    {
        $model = Yii::$app->user->identity;
        $model->clientid = null;
        $model->clearAccessToken();

        if (!$model->save()) {
            throw new HttpException(422, json_encode($model));
        }

        Yii::$app->getResponse()->setStatusCode(204);
    }

    /**
     * 访问令牌
     *
     * @return array
     * @throws \yii\web\HttpException
     */
    public function actionAccessToken()
    {
        $authorization = Yii::$app->request->post('authorization');

        if (!$authorization) {
            throw new HttpException(400, Yii::t('app/error', 'Parameter error.'));
        }

        $model = User::findIdentityByAuthKey($authorization, Yii::$app->request->userIP);

        if (strtotime($model->last_login_at) < time() - Yii::$app->params['authKeyPeriod']) {
            throw new HttpException(401, Yii::t('app/error', 'Authorization code has expired.'));
        }

        $model->generateAccessToken();
        $model->clearAuthKey();
        if ($model->save()) {
            return ['access_token' => $model->access_token];
        } else {
            throw new HttpException(500, json_encode($model));
        }
    }
}
