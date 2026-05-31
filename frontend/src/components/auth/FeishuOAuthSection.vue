<template>
  <div class="space-y-4">
    <div class="mx-auto flex w-fit max-w-full flex-col items-center rounded-lg border border-gray-200 bg-white p-1.5 dark:border-dark-600 dark:bg-dark-800">
      <div
        v-if="tenantOptions.length > 0"
        class="mb-1 flex min-h-[24px] w-full flex-wrap items-center justify-center gap-1"
      >
        <button
          v-for="tenant in tenantOptions"
          :key="tenant.tenant_key"
          type="button"
          :disabled="loading || tenantOptions.length === 1"
          class="rounded-full border px-2 py-0.5 text-xs font-medium transition-colors disabled:cursor-default disabled:opacity-100"
          :class="
            selectedTenantKey === tenant.tenant_key
              ? 'border-primary-500 bg-primary-50 text-primary-700 dark:border-primary-400 dark:bg-primary-900/30 dark:text-primary-200'
              : 'border-gray-200 text-gray-600 hover:border-primary-300 hover:text-primary-600 dark:border-dark-600 dark:text-dark-300 dark:hover:border-primary-500 dark:hover:text-primary-300'
          "
          @click="selectTenant(tenant.tenant_key)"
        >
          {{ tenant.name }}
        </button>
      </div>

      <div class="relative overflow-hidden rounded-md" style="width: 260px; height: 330px;">
        <div v-if="loading" class="flex h-full items-center justify-center">
          <span class="text-sm text-gray-500 dark:text-dark-400">
            {{ t('auth.feishu.loadingQR') }}
          </span>
        </div>
        <iframe
          v-else-if="qrPageURL"
          :src="qrPageURL"
          class="absolute border-0"
          style="left: -20px; top: -16px; width: 300px; height: 360px;"
        />
        <div
          v-else-if="status === 'error'"
          class="flex h-full flex-col items-center justify-center gap-2 text-center"
        >
          <p class="text-sm text-gray-500 dark:text-dark-400">{{ statusMessage }}</p>
          <button
            type="button"
            class="text-sm font-medium text-primary-600 hover:text-primary-500 dark:text-primary-400"
            @click="initQR"
          >
            {{ t('auth.feishu.refreshQR') }}
          </button>
        </div>
      </div>

      <p class="mt-1.5 text-center text-xs text-gray-500 dark:text-dark-400">
        {{ statusMessage || t('auth.feishu.scanHint') }}
      </p>

    </div>

    <div v-if="showDivider" class="flex items-center gap-3">
      <div class="h-px flex-1 bg-gray-200 dark:bg-dark-700"></div>
      <span class="text-xs text-gray-500 dark:text-dark-400">
        {{ t('auth.oauthOrContinue') }}
      </span>
      <div class="h-px flex-1 bg-gray-200 dark:bg-dark-700"></div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onBeforeUnmount, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { initFeishuOAuthQRCode } from '@/api/auth'
import { useAppStore } from '@/stores/app'
import { resolveAffiliateReferralCode, storeOAuthAffiliateCode } from '@/utils/oauthAffiliate'

const props = withDefaults(defineProps<{
  disabled?: boolean
  affCode?: string
  showDivider?: boolean
}>(), {
  showDivider: true
})

const route = useRoute()
const { t } = useI18n()
const appStore = useAppStore()

const qrPageURL = ref('')
const loading = ref(false)
const status = ref<'pending' | 'error'>('pending')
const statusMessage = ref('')
const redirectTo = ref('/dashboard')
const selectedTenantKey = ref('')
const tenantOptions = computed(() => appStore.cachedPublicSettings?.feishu_oauth_tenants ?? [])

function ensureSelectedTenant(): void {
  if (tenantOptions.value.length === 0) {
    selectedTenantKey.value = ''
    return
  }
  if (!tenantOptions.value.some((tenant) => tenant.tenant_key === selectedTenantKey.value)) {
    selectedTenantKey.value = tenantOptions.value[0]?.tenant_key || ''
  }
}

function selectTenant(tenantKey: string): void {
  if (loading.value || tenantKey === selectedTenantKey.value) return
  selectedTenantKey.value = tenantKey
  initQR()
}

function handleQRDebugMessage(event: MessageEvent): void {
  if (event.origin !== window.location.origin) {
    return
  }
  const data = event.data as { type?: string; step?: string; detail?: string }
  if (!data || data.type !== 'feishu_qr_debug') {
    return
  }
  // Keep this visible during the fragile third-party QR handoff.
  console.debug('[Feishu QR]', data.step, data.detail || '')
  if (data.step === 'tmp_code_received') {
    statusMessage.value = t('auth.feishu.redirecting')
  } else if (data.step === 'message_rejected' || data.step === 'tmp_code_missing' || data.step === 'error') {
    statusMessage.value = `${data.step}${data.detail ? `: ${data.detail}` : ''}`
  }
}

async function initQR(): Promise<void> {
  if (props.disabled) return

  loading.value = true
  qrPageURL.value = ''
  status.value = 'pending'
  statusMessage.value = ''

  try {
    redirectTo.value = (route.query.redirect as string) || '/dashboard'
    storeOAuthAffiliateCode(resolveAffiliateReferralCode(props.affCode, route.query.aff, route.query.aff_code))

    ensureSelectedTenant()
    const data = await initFeishuOAuthQRCode(redirectTo.value, selectedTenantKey.value || undefined)
    qrPageURL.value = data.qr_url
  } catch {
    status.value = 'error'
    statusMessage.value = t('auth.loginFailed')
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  window.addEventListener('message', handleQRDebugMessage)
  if (!appStore.cachedPublicSettings && !appStore.publicSettingsLoaded) {
    await appStore.fetchPublicSettings()
  }
  ensureSelectedTenant()
  initQR()
})

onBeforeUnmount(() => {
  window.removeEventListener('message', handleQRDebugMessage)
})

watch(
  () => props.disabled,
  (disabled, wasDisabled) => {
    if (wasDisabled && !disabled && !qrPageURL.value) {
      initQR()
    }
  }
)
</script>
