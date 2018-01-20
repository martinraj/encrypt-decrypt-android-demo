package com.example.marty.encryptdemo;

import android.os.Build;
import android.support.annotation.RequiresApi;
import android.support.design.widget.TextInputEditText;
import android.support.design.widget.TextInputLayout;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    TextView resultText;
    TextInputLayout textLayout;
    TextInputEditText eText;
    Button action1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        eText = (TextInputEditText)findViewById(R.id.t_e_text);
        textLayout = (TextInputLayout) findViewById(R.id.t_layout);
        resultText = (TextView)findViewById(R.id.result_text);
        action1 = (Button) findViewById(R.id.action_1);
        action1.setOnClickListener(this);
        EncUtil.generateKey(getApplicationContext());
    }


    private void ShortToast(String s) {
        Toast.makeText(getApplicationContext(),s,Toast.LENGTH_SHORT).show();
    }

    public void setTextInputLayoutError(TextInputLayout e, String error, Boolean errorEnabled){
        e.setError(error);
        e.setErrorEnabled(errorEnabled);
    }

    @Override
    public void onClick(View view) {
        if(view.getId()==R.id.action_1){
            if(action1.getTag().equals("e")){
                if(eText.getText().toString().trim().isEmpty()){
                    setTextInputLayoutError(textLayout,"Mandatory field",true);
                    return;
                }
                setTextInputLayoutError(textLayout,null,false);
                resultText.setText(EncUtil.encrypt(getApplicationContext(),eText.getText().toString().trim()));
                action1.setTag("d");
                action1.setText("DECRYPT USING APP INSTANCE");
            }else{
                if(resultText.getText().toString().isEmpty()){
                    ShortToast("empty data to decrypt");
                    return;
                }
                resultText.setText(EncUtil.decrypt(getApplicationContext(),resultText.getText().toString()));
                action1.setTag("e");
                action1.setText("ENCRYPT USING APP INSTANCE");
            }
        }
    }
}
