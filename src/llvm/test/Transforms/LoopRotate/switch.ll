; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -S -loop-rotate < %s | FileCheck %s

define i64 @switch_multi_entry_known_entry() {
; CHECK-LABEL: @switch_multi_entry_known_entry(
; CHECK-NEXT:  start:
; CHECK-NEXT:    br label [[HEADER:%.*]]
; CHECK:       header:
; CHECK-NEXT:    [[STATE:%.*]] = phi i8 [ 2, [[START:%.*]] ], [ [[NEXT_STATE:%.*]], [[LATCH:%.*]] ]
; CHECK-NEXT:    [[COUNT:%.*]] = phi i64 [ 0, [[START]] ], [ [[INC:%.*]], [[LATCH]] ]
; CHECK-NEXT:    switch i8 [[STATE]], label [[EXIT:%.*]] [
; CHECK-NEXT:    i8 0, label [[LATCH]]
; CHECK-NEXT:    i8 2, label [[LATCH]]
; CHECK-NEXT:    ]
; CHECK:       latch:
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i64 [[COUNT]], 999
; CHECK-NEXT:    [[NEXT_STATE]] = zext i1 [[CMP]] to i8
; CHECK-NEXT:    [[INC]] = add i64 [[COUNT]], 1
; CHECK-NEXT:    br label [[HEADER]]
; CHECK:       exit:
; CHECK-NEXT:    [[COUNT_LCSSA:%.*]] = phi i64 [ [[COUNT]], [[HEADER]] ]
; CHECK-NEXT:    ret i64 [[COUNT_LCSSA]]
;
start:
  br label %header

header:                                           ; preds = %latch, %start
  %state = phi i8 [ 2, %start ], [ %next_state, %latch ]
  %count = phi i64 [ 0, %start ], [ %inc, %latch ]
  switch i8 %state, label %exit [
  i8 0, label %latch
  i8 2, label %latch
  ]

latch:                                            ; preds = %header, %header
  %cmp = icmp eq i64 %count, 999
  %next_state = zext i1 %cmp to i8
  %inc = add i64 %count, 1
  br label %header

exit:                                             ; preds = %header
  ret i64 %count
}

define i64 @switch_multi_entry_unknown_entry(i8 %start_state) {
; CHECK-LABEL: @switch_multi_entry_unknown_entry(
; CHECK-NEXT:  start:
; CHECK-NEXT:    br label [[HEADER:%.*]]
; CHECK:       header:
; CHECK-NEXT:    [[STATE:%.*]] = phi i8 [ [[START_STATE:%.*]], [[START:%.*]] ], [ [[NEXT_STATE:%.*]], [[LATCH:%.*]] ]
; CHECK-NEXT:    [[COUNT:%.*]] = phi i64 [ 0, [[START]] ], [ [[INC:%.*]], [[LATCH]] ]
; CHECK-NEXT:    switch i8 [[STATE]], label [[EXIT:%.*]] [
; CHECK-NEXT:    i8 0, label [[LATCH]]
; CHECK-NEXT:    i8 2, label [[LATCH]]
; CHECK-NEXT:    ]
; CHECK:       latch:
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i64 [[COUNT]], 999
; CHECK-NEXT:    [[NEXT_STATE]] = zext i1 [[CMP]] to i8
; CHECK-NEXT:    [[INC]] = add i64 [[COUNT]], 1
; CHECK-NEXT:    br label [[HEADER]]
; CHECK:       exit:
; CHECK-NEXT:    [[COUNT_LCSSA:%.*]] = phi i64 [ [[COUNT]], [[HEADER]] ]
; CHECK-NEXT:    ret i64 [[COUNT_LCSSA]]
;
start:
  br label %header

header:                                           ; preds = %latch, %start
  %state = phi i8 [ %start_state, %start ], [ %next_state, %latch ]
  %count = phi i64 [ 0, %start ], [ %inc, %latch ]
  switch i8 %state, label %exit [
  i8 0, label %latch
  i8 2, label %latch
  ]

latch:                                            ; preds = %header, %header
  %cmp = icmp eq i64 %count, 999
  %next_state = zext i1 %cmp to i8
  %inc = add i64 %count, 1
  br label %header

exit:                                             ; preds = %header
  ret i64 %count
}

define i64 @switch_multi_exit_known_entry() {
; CHECK-LABEL: @switch_multi_exit_known_entry(
; CHECK-NEXT:  start:
; CHECK-NEXT:    br label [[HEADER:%.*]]
; CHECK:       header:
; CHECK-NEXT:    [[STATE:%.*]] = phi i8 [ 0, [[START:%.*]] ], [ [[NEXT_STATE:%.*]], [[LATCH:%.*]] ]
; CHECK-NEXT:    [[COUNT:%.*]] = phi i64 [ 0, [[START]] ], [ [[INC:%.*]], [[LATCH]] ]
; CHECK-NEXT:    switch i8 [[STATE]], label [[LATCH]] [
; CHECK-NEXT:    i8 1, label [[EXIT:%.*]]
; CHECK-NEXT:    i8 2, label [[EXIT]]
; CHECK-NEXT:    ]
; CHECK:       latch:
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i64 [[COUNT]], 999
; CHECK-NEXT:    [[NEXT_STATE]] = zext i1 [[CMP]] to i8
; CHECK-NEXT:    [[INC]] = add i64 [[COUNT]], 1
; CHECK-NEXT:    br label [[HEADER]]
; CHECK:       exit:
; CHECK-NEXT:    [[COUNT_LCSSA:%.*]] = phi i64 [ [[COUNT]], [[HEADER]] ], [ [[COUNT]], [[HEADER]] ]
; CHECK-NEXT:    ret i64 [[COUNT_LCSSA]]
;
start:
  br label %header

header:                                           ; preds = %latch, %start
  %state = phi i8 [ 0, %start ], [ %next_state, %latch ]
  %count = phi i64 [ 0, %start ], [ %inc, %latch ]
  switch i8 %state, label %latch [
  i8 1, label %exit
  i8 2, label %exit
  ]

latch:                                            ; preds = %header, %header
  %cmp = icmp eq i64 %count, 999
  %next_state = zext i1 %cmp to i8
  %inc = add i64 %count, 1
  br label %header

exit:                                             ; preds = %header
  ret i64 %count
}

define i64 @switch_multi_exit_unknown_entry(i8 %start_state) {
; CHECK-LABEL: @switch_multi_exit_unknown_entry(
; CHECK-NEXT:  start:
; CHECK-NEXT:    br label [[HEADER:%.*]]
; CHECK:       header:
; CHECK-NEXT:    [[STATE:%.*]] = phi i8 [ [[START_STATE:%.*]], [[START:%.*]] ], [ [[NEXT_STATE:%.*]], [[LATCH:%.*]] ]
; CHECK-NEXT:    [[COUNT:%.*]] = phi i64 [ 0, [[START]] ], [ [[INC:%.*]], [[LATCH]] ]
; CHECK-NEXT:    switch i8 [[STATE]], label [[LATCH]] [
; CHECK-NEXT:    i8 1, label [[EXIT:%.*]]
; CHECK-NEXT:    i8 2, label [[EXIT]]
; CHECK-NEXT:    ]
; CHECK:       latch:
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i64 [[COUNT]], 999
; CHECK-NEXT:    [[NEXT_STATE]] = zext i1 [[CMP]] to i8
; CHECK-NEXT:    [[INC]] = add i64 [[COUNT]], 1
; CHECK-NEXT:    br label [[HEADER]]
; CHECK:       exit:
; CHECK-NEXT:    [[COUNT_LCSSA:%.*]] = phi i64 [ [[COUNT]], [[HEADER]] ], [ [[COUNT]], [[HEADER]] ]
; CHECK-NEXT:    ret i64 [[COUNT_LCSSA]]
;
start:
  br label %header

header:                                           ; preds = %latch, %start
  %state = phi i8 [ %start_state, %start ], [ %next_state, %latch ]
  %count = phi i64 [ 0, %start ], [ %inc, %latch ]
  switch i8 %state, label %latch [
  i8 1, label %exit
  i8 2, label %exit
  ]

latch:                                            ; preds = %header, %header
  %cmp = icmp eq i64 %count, 999
  %next_state = zext i1 %cmp to i8
  %inc = add i64 %count, 1
  br label %header

exit:                                             ; preds = %header
  ret i64 %count
}
