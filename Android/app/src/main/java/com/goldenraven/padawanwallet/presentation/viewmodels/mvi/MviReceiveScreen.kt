/*
 * Copyright 2021-2024 thunderbiscuit and contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE file.
 */

package com.goldenraven.padawanwallet.presentation.viewmodels.mvi

import androidx.compose.runtime.Stable
import com.goldenraven.padawanwallet.utils.QrUiState

@Stable
data class ReceiveScreenState(
    val address: String? = null,
    val bip21Uri: String? = null,
    val addressIndex: Int? = null,
    val qrState: QrUiState = QrUiState.NoQR
)

sealed interface ReceiveScreenAction {
    data object UpdateAddress : ReceiveScreenAction
}
