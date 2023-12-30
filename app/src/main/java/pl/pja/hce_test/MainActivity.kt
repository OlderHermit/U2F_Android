package pl.pja.hce_test

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.datastore.core.DataStore
import androidx.datastore.dataStore
import kotlinx.coroutines.runBlocking


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

    private fun isMyServiceRunning(serviceClass: Class<*>): Boolean {
        val manager = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        for (service in manager.getRunningServices(Int.MAX_VALUE)) {
            if (serviceClass.name == service.service.className) {
                return true
            }
        }
        return false
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

