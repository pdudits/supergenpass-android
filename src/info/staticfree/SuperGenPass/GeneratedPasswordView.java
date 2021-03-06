package info.staticfree.SuperGenPass;

import android.app.Application;
import android.content.Context;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.ClipboardManager;
import android.text.InputType;
import android.text.TextUtils;
import android.text.method.NumberKeyListener;
import android.text.method.PasswordTransformationMethod;
import android.util.AttributeSet;
import android.util.Log;
import android.view.ContextMenu;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MenuItem.OnMenuItemClickListener;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.TextView;
import android.widget.Toast;

@SuppressWarnings("deprecation")
public class GeneratedPasswordView extends TextView implements OnClickListener, OnMenuItemClickListener {
    public final static int
        MENU_ID_COPY = android.R.id.copy;

    private OnClickListener onClickListener;
    private CharSequence domain;

    public GeneratedPasswordView(Context context) {
        this(context, null);
    }

    public GeneratedPasswordView(Context context, AttributeSet attrs){
        this(context, attrs, R.attr.generatedPasswordViewStyle);
    }

    public GeneratedPasswordView(Context context, AttributeSet attrs,
            int defStyle) {
        super(context, attrs, defStyle);

        super.setOnClickListener(this);

        setKeyListener(new NumberKeyListener() {
            public int getInputType() {
                return InputType.TYPE_NULL;
            }

            @Override
            protected char[] getAcceptedChars() {
                return new char[] {};
            }
        });
    }

    @Override
    public void setOnClickListener(OnClickListener l) {
        this.onClickListener = l;
    }

    public void onClick(View v) {
        Log.d("gpwv", "click!");

        // propagate the click
        if (onClickListener != null){
            onClickListener.onClick(v);
        }
    }

    @Override
    protected void onCreateContextMenu(ContextMenu menu) {
        menu.add(Menu.NONE, MENU_ID_COPY, Menu.NONE, android.R.string.copy).setOnMenuItemClickListener(this);
        menu.setHeaderTitle(R.string.generated_password);
    }

    @Override
    public boolean onTextContextMenuItem(int id) {
        switch (id){
        case MENU_ID_COPY:
            copyToClipboard();
            return true;

            default:
                return super.onTextContextMenuItem(id);
        }
    }

    /**
     * Sets the domain name that will be displayed when copying to clipboard.
     *
     * @param domainName
     */
    public void setDomainName(CharSequence domainName){
        this.domain = domainName;
    }

    @Override
    public void setText(CharSequence text, BufferType type) {
        super.setText(text, type);
        setEnabled(text != null ? text.length() > 0 : false);
    }

    public void copyToClipboard(){
        final CharSequence genPw = getText();
        if (genPw == null) {
            return;
        }

        final ClipboardManager clipMan = (ClipboardManager)getContext().getSystemService(Application.CLIPBOARD_SERVICE);
        clipMan.setText(genPw);
        if (genPw.length() > 0){
            if (domain != null){
                Toast.makeText(getContext(), getResources().getString(R.string.toast_copied, domain),
                        Toast.LENGTH_SHORT).show();
            }else{
                Toast.makeText(getContext(), getResources().getString(R.string.toast_copied_no_domain),
                        Toast.LENGTH_SHORT).show();
            }
        }
    }

    public void setHidePassword(boolean hidePassword) {
        if (hidePassword) {
            setTransformationMethod(PasswordTransformationMethod.getInstance());
        } else {
            setTransformationMethod(null);
        }
    }

    public boolean getHidePassword() {
        return getTransformationMethod() != null;
    }

    public boolean onMenuItemClick(MenuItem item) {
        return onTextContextMenuItem(item.getItemId());
    }


    /* (for all the state-related code below)
     *
     * Copyright (C) 2006 The Android Open Source Project
     *
     * Licensed under the Apache License, Version 2.0 (the "License");
     * you may not use this file except in compliance with the License.
     * You may obtain a copy of the License at
     *
     *      http://www.apache.org/licenses/LICENSE-2.0
     *
     * Unless required by applicable law or agreed to in writing, software
     * distributed under the License is distributed on an "AS IS" BASIS,
     * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     * See the License for the specific language governing permissions and
     * limitations under the License.
     */

    @Override
    public void onRestoreInstanceState(Parcelable state) {
        if (!(state instanceof SavedState)) {
            super.onRestoreInstanceState(state);
            return;
        }

        final SavedState ss = (SavedState)state;
        super.onRestoreInstanceState(ss.getSuperState());

        if (ss.text != null) {
            setText(ss.text);
        }
    }

    @Override
    public Parcelable onSaveInstanceState() {
        final Parcelable superState = super.onSaveInstanceState();

        final SavedState ss = new SavedState(superState);
        ss.text = getText();

        return ss;
    }

    public static class SavedState extends BaseSavedState {

        CharSequence text;

        public SavedState(Parcelable superState) {
            super(superState);

        }
        @Override
        public void writeToParcel(Parcel dest, int flags) {
            super.writeToParcel(dest, flags);

            TextUtils.writeToParcel(text, dest, flags);
        }

        public static final Parcelable.Creator<SavedState> CREATOR
                = new Parcelable.Creator<SavedState>() {
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in);
            }

            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };

        private SavedState(Parcel in) {
            super(in);
            text = TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(in);
        }
    }
    /* end Copyright (C) 2006 The Android Open Source Project */
}
