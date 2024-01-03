package pl.pja.hce_test

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.widget.Button
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity


class MainActivity : AppCompatActivity() {

    private lateinit var bt: Button
    private lateinit var myIntent: Intent

    @RequiresApi(Build.VERSION_CODES.S)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        bt = findViewById(R.id.bt_test)
        bt.setOnClickListener {
            shouldClean = true
            //Log.d("HCE", isMyServiceRunning(MyHostApduService::class.java).toString())
        }

        myIntent = Intent(this, MyHostApduService::class.java)
        startService(myIntent)
        shouldWork = true
    }

    override fun onDestroy() {
        shouldWork = false
        super.onDestroy()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        shouldWork = hasFocus
        super.onWindowFocusChanged(hasFocus)
    }

    companion object {
        private var shouldWork: Boolean = false
        private var shouldClean: Boolean = false
        fun shouldWork(): Boolean = shouldWork
        fun shouldClean(): Boolean = shouldClean
        fun cleaned() {
            shouldClean = false
        }
    }

}

