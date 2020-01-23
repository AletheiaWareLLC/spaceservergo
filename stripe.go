/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import "github.com/stripe/stripe-go"

func StripeEventHandler(event *stripe.Event) {
	switch event.Type {
	case "account.updated":
		// TODO mine event into BC
	case "account.external_account.created":
		// TODO mine event into BC
	case "account.external_account.deleted":
		// TODO mine event into BC
	case "account.external_account.updated":
		// TODO mine event into BC
	case "balance.available":
		// TODO mine event into BC
	case "capability.updated":
		// TODO mine event into BC
	case "charge.captured":
		// TODO mine event into BC
	case "charge.expired":
		// TODO mine event into BC
	case "charge.failed":
		// TODO mine event into BC
	case "charge.pending":
		// TODO mine event into BC
	case "charge.refunded":
		// TODO mine event into BC
	case "charge.succeeded":
		// TODO mine event into BC
	case "charge.updated":
		// TODO mine event into BC
	case "charge.dispute.closed":
		// TODO mine event into BC
	case "charge.dispute.created":
		// TODO mine event into BC
	case "charge.dispute.funds_reinstated":
		// TODO mine event into BC
	case "charge.dispute.funds_withdrawn":
		// TODO mine event into BC
	case "charge.dispute.updated":
		// TODO mine event into BC
	case "charge.refund.updated":
		// TODO mine event into BC
	case "checkout.session.completed":
		// TODO mine event into BC
	case "coupon.created":
		// TODO mine event into BC
	case "coupon.deleted":
		// TODO mine event into BC
	case "coupon.updated":
		// TODO mine event into BC
	case "credit_note.created":
		// TODO mine event into BC
	case "credit_note.updated":
		// TODO mine event into BC
	case "credit_note.voided":
		// TODO mine event into BC
	case "customer.created":
		// TODO mine event into BC
	case "customer.deleted":
		// TODO mine event into BC
	case "customer.updated":
		// TODO mine event into BC
	case "customer.bank_account.deleted":
		// TODO mine event into BC
	case "customer.discount.created":
		// TODO mine event into BC
	case "customer.discount.deleted":
		// TODO mine event into BC
	case "customer.discount.updated":
		// TODO mine event into BC
	case "customer.source.created":
		// TODO mine event into BC
	case "customer.source.deleted":
		// TODO mine event into BC
	case "customer.source.expiring":
		// TODO mine event into BC
	case "customer.source.updated":
		// TODO mine event into BC
	case "customer.subscription.created":
		// TODO mine event into BC
	case "customer.subscription.deleted":
		// TODO mine event into BC
	case "customer.subscription.trial_will_end":
		// TODO mine event into BC
	case "customer.subscription.updated":
		// TODO mine event into BC
	case "customer.tax_id.created":
		// TODO mine event into BC
	case "customer.tax_id.deleted":
		// TODO mine event into BC
	case "customer.tax_id.updated":
		// TODO mine event into BC
	case "file.created":
		// TODO mine event into BC
	case "invoice.created":
		// TODO mine event into BC
	case "invoice.deleted":
		// TODO mine event into BC
	case "invoice.finalized":
		// TODO mine event into BC
	case "invoice.marked_uncollectible":
		// TODO mine event into BC
	case "invoice.payment_action_required":
		// TODO mine event into BC
	case "invoice.payment_failed":
		// TODO mine event into BC
	case "invoice.payment_succeeded":
		// TODO mine event into BC
	case "invoice.sent":
		// TODO mine event into BC
	case "invoice.upcoming":
		// TODO mine event into BC
	case "invoice.updated":
		// TODO mine event into BC
	case "invoice.voided":
		// TODO mine event into BC
	case "invoiceitem.created":
		// TODO mine event into BC
	case "invoiceitem.deleted":
		// TODO mine event into BC
	case "invoiceitem.updated":
		// TODO mine event into BC
	case "issuing_authorization.created":
		// TODO mine event into BC
	case "issuing_authorization.request":
		// TODO mine event into BC
	case "issuing_authorization.updated":
		// TODO mine event into BC
	case "issuing_card.created":
		// TODO mine event into BC
	case "issuing_card.updated":
		// TODO mine event into BC
	case "issuing_cardholder.created":
		// TODO mine event into BC
	case "issuing_cardholder.updated":
		// TODO mine event into BC
	case "issuing_dispute.created":
		// TODO mine event into BC
	case "issuing_dispute.updated":
		// TODO mine event into BC
	case "issuing_settlement.created":
		// TODO mine event into BC
	case "issuing_settlement.updated":
		// TODO mine event into BC
	case "issuing_transaction.created":
		// TODO mine event into BC
	case "issuing_transaction.updated":
		// TODO mine event into BC
	case "order.created":
		// TODO mine event into BC
	case "order.payment_failed":
		// TODO mine event into BC
	case "order.payment_succeeded":
		// TODO mine event into BC
	case "order.updated":
		// TODO mine event into BC
	case "order_return.created":
		// TODO mine event into BC
	case "payment_intent.amount_capturable_updated":
		// TODO mine event into BC
	case "payment_intent.created":
		// TODO mine event into BC
	case "payment_intent.payment_failed":
		// TODO mine event into BC
	case "payment_intent.succeeded":
		// TODO mine event into BC
	case "payment_method.attached":
		// TODO mine event into BC
	case "payment_method.card_automatically_updated":
		// TODO mine event into BC
	case "payment_method.detached":
		// TODO mine event into BC
	case "payment_method.updated":
		// TODO mine event into BC
	case "payout.canceled":
		// TODO mine event into BC
	case "payout.created":
		// TODO mine event into BC
	case "payout.failed":
		// TODO mine event into BC
	case "payout.paid":
		// TODO mine event into BC
	case "payout.updated":
		// TODO mine event into BC
	case "person.created":
		// TODO mine event into BC
	case "person.deleted":
		// TODO mine event into BC
	case "person.updated":
		// TODO mine event into BC
	case "plan.created":
		// TODO mine event into BC
	case "plan.deleted":
		// TODO mine event into BC
	case "plan.updated":
		// TODO mine event into BC
	case "product.created":
		// TODO mine event into BC
	case "product.deleted":
		// TODO mine event into BC
	case "product.updated":
		// TODO mine event into BC
	case "radar.early_fraud_warning.created":
		// TODO mine event into BC
	case "radar.early_fraud_warning.updated":
		// TODO mine event into BC
	case "recipient.created":
		// TODO mine event into BC
	case "recipient.deleted":
		// TODO mine event into BC
	case "recipient.updated":
		// TODO mine event into BC
	case "reporting.report_run.failed":
		// TODO mine event into BC
	case "reporting.report_run.succeeded":
		// TODO mine event into BC
	case "reporting.report_type.updated":
		// TODO mine event into BC
	case "review.closed":
		// TODO mine event into BC
	case "review.opened":
		// TODO mine event into BC
	case "setup_intent.created":
		// TODO mine event into BC
	case "setup_intent.setup_failed":
		// TODO mine event into BC
	case "setup_intent.succeeded":
		// TODO mine event into BC
	case "sigma.scheduled_query_run.created":
		// TODO mine event into BC
	case "sku.created":
		// TODO mine event into BC
	case "sku.deleted":
		// TODO mine event into BC
	case "sku.updated":
		// TODO mine event into BC
	case "source.canceled":
		// TODO mine event into BC
	case "source.chargeable":
		// TODO mine event into BC
	case "source.failed":
		// TODO mine event into BC
	case "source.mandate_notification":
		// TODO mine event into BC
	case "source.refund_attributes_required":
		// TODO mine event into BC
	case "source.transaction.created":
		// TODO mine event into BC
	case "source.transaction.updated":
		// TODO mine event into BC
	case "tax_rate.created":
		// TODO mine event into BC
	case "tax_rate.updated":
		// TODO mine event into BC
	case "topup.canceled":
		// TODO mine event into BC
	case "topup.created":
		// TODO mine event into BC
	case "topup.failed":
		// TODO mine event into BC
	case "topup.reversed":
		// TODO mine event into BC
	case "topup.succeeded":
		// TODO mine event into BC
	case "transfer.created":
		// TODO mine event into BC
	case "transfer.failed":
		// TODO mine event into BC
	case "transfer.paid":
		// TODO mine event into BC
	case "transfer.reversed":
		// TODO mine event into BC
	case "transfer.updated":
		// TODO mine event into BC
	}
}
