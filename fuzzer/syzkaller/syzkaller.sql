WITH `base` AS (
  SELECT
    DISTINCT
    `syzkaller`,
    (
        SELECT
          `commit`
        FROM
          `tags`
        WHERE
          `commit` = `fixed_by`
    ) `fixed_by`,
    IIF(
      LENGTH(`introduced_by_short`)<4,
      null,
      (
        SELECT
          `commit`
        FROM
          `tags`
        WHERE
          `commit` >= `introduced_by_short`
          AND `commit` < `introduced_by_short`||"g"
      )
    ) `introduced_by`
  FROM
    (
      SELECT
        `syzkaller`,
        `fixed_by`,
        (
          SELECT
            SUBSTR(`fixes`, 0, INSTR(`fixes`, " "))
          FROM
            `fixes`
          WHERE
            `commit` = `fixed_by`
        ) `introduced_by_short`
      FROM
        (
          SELECT
            SUBSTRING(
              `reported_by`,
              INSTR(`reported_by`, "syzbot+") + LENGTH("syzbot+"),
              INSTR(`reported_by`, "@") - INSTR(`reported_by`, "syzbot+") - LENGTH("syzbot+")
            ) `syzkaller`,
            `commit` `fixed_by`
          FROM
            `reported_by`
          WHERE
            `reported_by`
          LIKE
            "%syzbot+%"
          UNION ALL
          SELECT
            `syzkaller`,
            `commit` `fixed_by`
          FROM
            `syzkaller`
        )
    )
  WHERE
    `introduced_by` is not null
  ),
`tagged` AS
  (
    SELECT
      `syzkaller`,
      `fixed_by`,
      (
        SELECT
          SUBSTR(`tags`, 0, MIN(INSTR(`tags`||'~', '~'), INSTR(`tags`||'-', '-')))
        FROM
          `tags`
        WHERE
          `commit`=`fixed_by`
      ) `fixed_by_tag`,
      `introduced_by`,
      (
        SELECT
          SUBSTR(`tags`, 0, MIN(INSTR(`tags`||'~', '~'), INSTR(`tags`||'-', '-')))
        FROM
          `tags`
        WHERE
          `commit`=`introduced_by`
      ) `introduced_by_tag`
    FROM
      `base`
  ),
`relevant` AS
  (
    SELECT
      `syzkaller`,
      `introduced_by`,
      `fixed_by`,
      (SELECT `cve` FROM `cve` WHERE `commit`=`fixed_by`) `cve`
    FROM
      `tagged`
    WHERE
      `fixed_by_tag`<>`introduced_by_tag`
  )
SELECT * FROM `relevant`;